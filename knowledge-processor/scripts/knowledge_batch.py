#!/usr/bin/env python3
"""Reusable local cache validation and conditional batch commit. No semantic engine."""
import argparse, hashlib, json, os, re, stat, sys, time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import knowledge_io as io

@contextmanager
def exclusive(handle):
    handle.seek(0)
    if os.name=='nt':
        import msvcrt
        msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:yield
    finally:
        handle.seek(0)
        if os.name=='nt':msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
        else:fcntl.flock(handle.fileno(),fcntl.LOCK_UN)

def cache_check(work,request,cache):
    reasons=[]
    for field in ('stage','policy_sig','producer_sig','inputs'):
        if not request.get(field) or cache.get(field)!=request[field]:reasons.append('changed_or_missing:'+field)
    if cache.get('status')!='complete' or cache.get('coverage_complete') is not True:reasons.append('incomplete')
    for kind,items in [('input',request.get('inputs',[])),('artifact',cache.get('artifacts',[]))]:
        if not isinstance(items,list) or not items:reasons.append('missing:'+kind);continue
        for item in items:
            path=io.safe(work,item.get('path'))
            try:
                if not io.sha(item.get('sha256')) or io.digest(path)!=item['sha256']:reasons.append(kind+':changed:'+item['path'])
            except FileNotFoundError:reasons.append(kind+':missing:'+item['path'])
    return {'reusable':not reasons,'reasons':reasons,'artifacts':cache.get('artifacts',[]) if not reasons else [],'semantic_review':False}

def write_new(path,data):
    with path.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())

def commit(root,work,plan):
    start=time.monotonic();task=plan.get('task_id','')
    if not re.fullmatch(r'[A-Za-z0-9_\-\u4e00-\u9fff]{1,100}',task):raise ValueError('invalid task_id')
    if not plan.get('authority_ref') or not plan.get('reason'):raise ValueError('authority_ref and reason required')
    files=plan.get('files');protected=plan.get('protected_prefixes',[])
    if not isinstance(files,list) or not files:raise ValueError('nonempty files required')
    if not isinstance(protected,list):raise ValueError('protected_prefixes must be a list')
    for prefix in protected:io.safe(root,prefix)
    targets=set();entries=[]
    for item in files:
        rel=item.get('path');target=io.safe(root,rel);source=io.safe(work,item.get('candidate'))
        if rel in targets:raise ValueError('duplicate target')
        targets.add(rel)
        if rel.startswith(('管理/更新计划/','管理/历史版本/','管理/日志/')):raise ValueError('reserved commit metadata target')
        if any(rel==p or rel.startswith(p+'/') for p in protected):raise ValueError('protected target')
        if not io.sha(item.get('candidate_sha256')) or io.digest(source)!=item['candidate_sha256']:raise ValueError('candidate changed')
        if 'before_sha256' not in item or item['before_sha256'] is not None and not io.sha(item['before_sha256']):raise ValueError('explicit before_sha256 required')
        entries.append((item,target,source))
    meta=io.safe(root,'管理/更新计划/'+task,mkdir=True)
    receipt=io.safe(root,'管理/更新计划/'+task+'/批处理状态.json')
    lockfile=io.safe(root,'管理/更新计划/'+task+'/提交.lock')
    plan_hash=hashlib.sha256(json.dumps(plan,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    with lockfile.open('a+b',buffering=0) as gate,exclusive(gate):
        if receipt.exists():
            prior=io.read_json(receipt)
            if prior.get('plan_sha256')!=plan_hash:raise ValueError('task_id already has a different plan')
            if prior.get('status')=='committed':
                for item,target,_ in entries:
                    if io.digest(target)!=item['candidate_sha256']:raise ValueError('committed target changed')
                io.record(root,prior['event'])
                return {'status':'committed','reused':True,'changed':prior['changed'],'seconds':time.monotonic()-start}
            raise ValueError('unfinished transaction: inspect receipt and snapshots before recovery')
        for item,target,_ in entries:
            before=item['before_sha256']
            if before is None:
                if target.exists():raise ValueError('new target exists: '+item['path'])
            elif io.digest(target)!=before:raise ValueError('target changed: '+item['path'])
        stamp=datetime.now().astimezone().isoformat()
        event=dict(event_id=task+'-prepared',task_id=task,time=stamp,stage='提交',action='批量条件写入',status='prepared',targets=list(targets),reason=plan['reason'],authority_ref=plan['authority_ref'],plan_sha256=plan_hash)
        state=dict(plan_sha256=plan_hash,status='prepared',applied=[],plan=plan)
        write_new(receipt,(json.dumps(state,ensure_ascii=False,indent=2)+'\n').encode())
        io.record(root,event)
        try:
            for item,target,source in entries:
                before=item['before_sha256']
                if before==item['candidate_sha256']:continue
                io.safe(root,str(Path(item['path']).parent).replace('\\','/'),mkdir=True) if '/' in item['path'] else None
                data=source.read_bytes()
                if hashlib.sha256(data).hexdigest()!=item['candidate_sha256']:raise ValueError('candidate changed during commit')
                if before is None:write_new(target,data)
                else:
                    with target.open('r+b') as f,exclusive(f):
                        original=f.read()
                        if hashlib.sha256(original).hexdigest()!=before:raise ValueError('target changed at write')
                        snapshot=io.safe(root,'管理/历史版本/'+task+'/'+item['path'])
                        io.safe(root,'管理/历史版本/'+task+'/'+str(Path(item['path']).parent).replace('\\','/'),mkdir=True) if '/' in item['path'] else io.safe(root,'管理/历史版本/'+task,mkdir=True)
                        write_new(snapshot,original)
                        f.seek(0);f.write(data);f.truncate();f.flush();os.fsync(f.fileno())
                if io.digest(target)!=item['candidate_sha256']:raise ValueError('write verification failed')
                state['applied'].append(item['path'])
                receipt.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
            for item,target,_ in entries:
                if io.digest(target)!=item['candidate_sha256']:raise ValueError('final verification failed')
            event.update(event_id=task+'-committed',time=datetime.now().astimezone().isoformat(),status='committed',stage='验证')
            state.update(status='committed',changed=len(state['applied']),event=event)
            receipt.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
            io.record(root,event)
            return {'status':'committed','changed':state['changed'],'reused':False,'seconds':time.monotonic()-start,'semantic_review':False}
        except Exception as exc:
            state.update(status='failed',error=str(exc));receipt.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
            event.update(event_id=task+'-failed',time=datetime.now().astimezone().isoformat(),status='failed',error=str(exc));io.record(root,event);raise

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('cache-check');c.add_argument('--work',required=True);c.add_argument('--request',required=True);c.add_argument('--cache',required=True)
    c=sub.add_parser('commit');c.add_argument('--root',required=True);c.add_argument('--work',required=True);c.add_argument('--plan',required=True)
    a=p.parse_args()
    try:
        result=cache_check(io.root_path(a.work),io.read_json(a.request),io.read_json(a.cache)) if a.command=='cache-check' else commit(io.root_path(a.root),io.root_path(a.work),io.read_json(a.plan))
        print(json.dumps(result,ensure_ascii=False))
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=False));sys.exit(1)
if __name__=='__main__':main()
