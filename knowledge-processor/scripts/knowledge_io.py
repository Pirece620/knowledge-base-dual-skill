#!/usr/bin/env python3
"""Small local helpers: fingerprints, artifact verification, locked JSONL append.

No semantic extraction, model calls, knowledge publication or automatic recovery.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
from datetime import datetime

STATUSES={'received','classified','planned','prepared','applied','committed',
          'skipped','deferred','conflict','failed','rolled_back','rollback_failed'}

def pairs(items):
    result={}
    for key,value in items:
        if key in result: raise ValueError('duplicate JSON key')
        result[key]=value
    return result

def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'),object_pairs_hook=pairs)

def plain(path):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
        raise ValueError('symlinks and reparse points are not accepted')
    return info

def root_path(value):
    root=Path(os.path.abspath(Path(value).expanduser()))
    if not stat.S_ISDIR(plain(root).st_mode): raise ValueError('root must exist as a plain directory')
    return root.resolve()

def safe(root,relative,*,mkdir=False):
    if not isinstance(relative,str) or not relative or relative=='.' or '\\' in relative:
        raise ValueError('path must be nonempty root-relative POSIX text')
    parts=PurePosixPath(relative)
    if (parts.is_absolute() or parts.as_posix()!=relative or any(p in {'.','..'} or ':' in p for p in parts.parts)):
        raise ValueError('unsafe root-relative path')
    path=root
    for index,part in enumerate(parts.parts):
        path=path/part
        try: info=plain(path)
        except FileNotFoundError:
            if mkdir:
                try:path.mkdir()
                except FileExistsError:pass
                info=plain(path)
            else:continue
        if index<len(parts.parts)-1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError('parent is not a directory')
    if not path.resolve().is_relative_to(root): raise ValueError('path escapes root')
    return path

def digest(path):
    before=plain(path)
    if not stat.S_ISREG(before.st_mode):raise ValueError('hash input must be a regular file')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags)
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):
            raise ValueError('file changed before hashing')
        h=hashlib.sha256()
        while True:
            chunk=os.read(fd,1024*1024)
            if not chunk:break
            h.update(chunk)
        after=os.fstat(fd)
        if any(getattr(opened,k)!=getattr(after,k) for k in ('st_size','st_mtime_ns','st_ino','st_dev')):
            raise ValueError('file changed during hashing')
        return h.hexdigest()
    finally:os.close(fd)

def sha(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None

def verify(root,manifest):
    if not isinstance(manifest,dict) or manifest.get('schema')!='knowledge-artifacts.v1':
        raise ValueError('manifest schema must be knowledge-artifacts.v1')
    entries=manifest.get('artifacts')
    if not isinstance(entries,list):raise ValueError('artifacts must be an array')
    for item in entries:
        if not isinstance(item,dict) or not sha(item.get('sha256')):raise ValueError('invalid artifact')
        if digest(safe(root,item.get('path')))!=item['sha256']:
            raise ValueError('artifact hash differs: '+item['path'])
    return {'verified':len(entries),'semantic_review':False}

@contextmanager
def lock(root,timeout=5.0):
    safe(root,'管理/日志',mkdir=True)
    guard=safe(root,'管理/日志/操作日志.guard')
    handle=open(guard,'a+b',buffering=0)
    held=False
    try:
        deadline=time.monotonic()+timeout
        while True:
            try:
                handle.seek(0)
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                held=True;break
            except OSError:
                if time.monotonic()>=deadline:raise ValueError('log lock timeout')
                time.sleep(.05)
        plain(guard)
        yield
    finally:
        if held:
            handle.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(),fcntl.LOCK_UN)
        handle.close()

def record(root,event):
    if not isinstance(event,dict):raise ValueError('event must be an object')
    for key in ('event_id','task_id','stage','action','reason','time'):
        if not isinstance(event.get(key),str) or not event[key].strip():raise ValueError('missing event field: '+key)
    if event.get('status') not in STATUSES:raise ValueError('invalid event status')
    if datetime.fromisoformat(event['time'].replace('Z','+00:00')).utcoffset() is None:
        raise ValueError('event time needs timezone')
    if not isinstance(event.get('targets'),list):raise ValueError('targets must be an array')
    for target in event['targets']:
        relative=target.get('path') if isinstance(target,dict) else target
        safe(root,relative)
        if isinstance(target,dict):
            for key in ('before_sha256','after_sha256','candidate_sha256'):
                if target.get(key) is not None and not sha(target[key]):raise ValueError('invalid '+key)
            if event['status']=='committed' and target.get('after_sha256') is not None:
                if digest(safe(root,relative))!=target['after_sha256']:
                    raise ValueError('committed target hash does not match')
    legacy=root/'依赖/日志/操作日志.jsonl'
    if legacy.exists() and not (root/'管理/日志/操作日志.jsonl').exists():
        raise ValueError('legacy log exists; migrate it before starting a new event stream')
    with lock(root):
        path=safe(root,'管理/日志/操作日志.jsonl')
        if path.exists():
            if not stat.S_ISREG(plain(path).st_mode):raise ValueError('log must be a regular file')
            with path.open('rb') as source:
                for line in source:
                    if not line.endswith(b'\n'):raise ValueError('incomplete log tail; preserve and recover before appending')
                    prior=json.loads(line.decode('utf-8'),object_pairs_hook=pairs)
                    if not isinstance(prior,dict):raise ValueError('corrupt log event')
                    if prior.get('event_id')==event['event_id']:
                        if prior!=event:raise ValueError('event_id reused for different content')
                        return {'recorded':False,'reused':True,'event_id':event['event_id']}
        with path.open('ab') as sink:
            sink.write((json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8'))
            sink.flush();os.fsync(sink.fileno())
    return {'recorded':True,'event_id':event['event_id']}

def layout(value,topic=None):
    base=Path(os.path.abspath(Path(value).expanduser()))
    if not base.exists():
        missing=[]; parent=base
        while not parent.exists():
            missing.insert(0,parent.name); parent=parent.parent
        base=safe(root_path(parent),'/'.join(missing),mkdir=True)
    root=root_path(base)
    created=[]
    for name in ('附件','管理','来源','依赖','正文'):
        path=root/name; existed=path.exists(); safe(root,name,mkdir=True)
        if not stat.S_ISDIR(plain(path).st_mode):raise ValueError('layout name is occupied by a file: '+name)
        if not existed:created.append(name+'/')
    entries=[('00_先看这里.md','# '+root.name+'：先看这里\n\n正文按主题存放在[正文](正文/)，附件按来源分组保存在[附件](附件/)，原件与转换稿在[来源](来源/)，批次来源说明在[依赖](依赖/)，日志与状态在[管理](管理/)。\n\n当前入口为初始化导航，正式交付前需补齐具体任务、主题入口、阅读顺序及可用文件链接。\n')]
    for name in ('附件','管理','来源','依赖','正文'):
        entries.append((name+'/00_先看这里.md','# '+name+'：先看这里\n\n本层目录入口。正式交付前按实际直属内容填写索引与概述；内容变化后同步维护。正文只导航当前层，主题内部内容进入下一层查看。\n\n[返回总入口](../00_先看这里.md)\n'))
    if topic is not None:
        if not topic or any(c in topic for c in '/\\:') or topic in {'.','..'}:
            raise ValueError('topic must be one directory name')
        folder='正文/'+topic; safe(root,folder,mkdir=True)
        entries.append((folder+'/00_先看这里.md','# '+topic+'：先看这里\n\n本目录存放该主题的知识文件。正式交付前应填写“我要做什么 → 看哪份文件”、必要使用顺序和配套资源。\n\n[返回正文索引](../00_先看这里.md)\n'))
    for relative,text in entries:
        path=safe(root,relative)
        if path.exists():
            if not stat.S_ISREG(plain(path).st_mode):raise ValueError('entry path is not a regular file')
            continue
        try:
            with path.open('x',encoding='utf-8',newline='\n') as sink:
                sink.write(text);sink.flush();os.fsync(sink.fileno())
            created.append(relative)
        except FileExistsError:pass
    return {'created':created,'root':str(root),'existing_content_preserved':True,'entry_requires_editorial_completion':True}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    p=commands.add_parser('layout');p.add_argument('--root',required=True);p.add_argument('--topic')
    p=commands.add_parser('hash');p.add_argument('paths',nargs='+')
    p=commands.add_parser('verify');p.add_argument('--root',required=True);p.add_argument('--manifest',required=True)
    p=commands.add_parser('record');p.add_argument('--root',required=True);p.add_argument('--event',required=True)
    args=parser.parse_args()
    try:
        if args.command=='layout':result=layout(args.root,args.topic)
        elif args.command=='hash':result={'files':[{'path':x,'sha256':digest(Path(x))} for x in args.paths]}
        elif args.command=='verify':result=verify(root_path(args.root),read_json(args.manifest))
        else:result=record(root_path(args.root),read_json(args.event))
        print(json.dumps(result,ensure_ascii=False));return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=False),file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
