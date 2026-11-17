#!/usr/bin/env python3
"""Dependency-free Markdown checks; does not replace visual/semantic review."""
import argparse,json,re,sys
from pathlib import Path

def check(text,expect_fences=None,expect_cases=None):
    errors=[];warnings=[];fence=None;blocks=0;cases=0;lines=text.splitlines()
    for i,line in enumerate(lines):
        s=line.strip();m=re.match(r"^(`{3,}|~{3,})(.*)$",s)
        if m:
            mark=m.group(1)
            if fence is None:fence=mark;blocks+=1
            elif mark[0]==fence[0] and len(mark)>=len(fence) and not m.group(2).strip():fence=None
            continue
        if fence:continue
        if re.match(r"^### +[0-9]+(?:[ .、]|$)",s):cases+=1
        if re.fullmatch(r"\[(任务|画面风格|要求|输出格式|分镜镜头详情)\].*",s):warnings.append(dict(line=i+1,kind="naked_template_field"))
        if re.fullmatch(r"(海螺\s*[0-9.]*|即梦|Seedance\s*[0-9.]*)[（(]?",s):warnings.append(dict(line=i+1,kind="bare_tool_label"))
        if s.startswith("|") and s.endswith("|") and i+1<len(lines):
            prev=lines[i-1].strip() if i else ""
            nextline=lines[i+1].strip()
            if not prev.startswith("|") and nextline.startswith("|"):
                cells=[c.strip() for c in nextline.strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?",c) for c in cells):errors.append(dict(line=i+1,kind="missing_table_separator"))
    if fence:errors.append(dict(line=len(lines),kind="unclosed_fence"))
    if expect_fences is not None and blocks!=expect_fences:errors.append(dict(kind="fence_count",expected=expect_fences,actual=blocks))
    if expect_cases is not None and cases!=expect_cases:errors.append(dict(kind="case_count",expected=expect_cases,actual=cases))
    return dict(errors=errors,warnings=warnings,fences=blocks,cases=cases,passed=not errors,visual_review=False,semantic_review=False)

def main():
    p=argparse.ArgumentParser();p.add_argument("--file",required=True);p.add_argument("--expect-fences",type=int);p.add_argument("--expect-cases",type=int);a=p.parse_args()
    result=check(Path(a.file).read_text(encoding="utf-8-sig"),a.expect_fences,a.expect_cases)
    print(json.dumps(result,ensure_ascii=False));sys.exit(0 if result["passed"] else 1)
if __name__=="__main__":main()
