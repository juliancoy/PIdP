"""Build a minimal scope update over a verified deployed Worker bundle.

This avoids shipping unrelated identity changes or pending database migrations.
The equivalent source change must exist in both maintained implementations.
"""
import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path

BASELINE_SHA256='a512dc10bfb4587b9545c74acd8011f7c15450c07f717260f8901385e53b2d79'
ORIGINAL='var scopes = ["org:events.read", "org:events.write", "org:portal.read", "org:portal.write", "swarm:control"]'
UPDATED=ORIGINAL[:-1]+', "genomics:data"]'


def build(baseline,output,project):
    raw=base64.b64decode(Path(baseline).read_text().strip(),validate=True)
    if hashlib.sha256(raw).hexdigest()!=BASELINE_SHA256:raise ValueError('Deployed baseline digest differs')
    code=raw.decode()
    if code.count(ORIGINAL)!=1:raise ValueError('Scope declaration must occur exactly once')
    python=ast.parse((project/'mcp_authorization.py').read_text())
    values=next(ast.literal_eval(n.value) for n in python.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SCOPES' for t in n.targets))
    if values!=['org:events.read','org:events.write','org:portal.read','org:portal.write','swarm:control','genomics:data']:
        raise ValueError('Python scope contract differs')
    expected="const scopes = ['org:events.read', 'org:events.write', 'org:portal.read', 'org:portal.write', 'swarm:control', 'genomics:data'];"
    if expected not in (project/'serverless/src/mcpAuthorization.ts').read_text():raise ValueError('Worker scope contract differs')
    result=code.replace(ORIGINAL,UPDATED).encode();output=Path(output)
    output.write_bytes(result)
    receipt={'baseline_version':'19aa74ae-31f6-442d-8823-cd36f5d42a3f','baseline_sha256':BASELINE_SHA256,
             'result_sha256':hashlib.sha256(result).hexdigest(),'change':'Add genomics:data to the supported OAuth scopes','changed_declarations':1}
    output.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--baseline',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(build(args.baseline,args.output,Path(__file__).resolve().parents[1])))
