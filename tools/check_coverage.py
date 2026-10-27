"""Merge complementary startup coverage; fail closed on missing production sources."""
from pathlib import Path
import hashlib,json,sys

ROOT=Path(__file__).resolve().parents[1]
# Reviewed declaration-only interfaces: the Dart VM emits no executable lines.
DECLARATIONS={'lib/domain/ports.dart':'04edab68dd6e275d7262cbba38bd620329010c64466f72170c14b64ff01a6ca8'}

def check(reports):
    records={}
    for report in reports:
        current=None
        for row in report.read_text().splitlines():
            if row.startswith('SF:'):
                path=(ROOT/row[3:]).resolve()
                if not path.is_relative_to(ROOT/'lib') or not path.is_file():
                    raise ValueError('Unexpected coverage source')
                current=path.relative_to(ROOT).as_posix();records.setdefault(current,{})
            elif row.startswith('DA:'):
                if current is None:raise ValueError('Coverage line without source')
                line,hits,*_=row[3:].split(',');line,hits=int(line),int(hits)
                if line<1 or hits<0 or line>len((ROOT/current).read_text().splitlines()):
                    raise ValueError('Invalid coverage line')
                records[current][line]=max(hits,records[current].get(line,0))
            elif row=='end_of_record':current=None
    for name,digest in DECLARATIONS.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Declaration inventory changed; review executable coverage: '+name)
    expected={p.relative_to(ROOT).as_posix() for p in (ROOT/'lib').rglob('*.dart')}-DECLARATIONS.keys()
    if records.keys()!=expected or any(not lines for lines in records.values()):
        raise ValueError('Missing/empty source coverage: '+str(expected-records.keys()))
    total=sum(len(lines) for lines in records.values())
    covered=sum(v>0 for lines in records.values() for v in lines.values())
    critical={name for name in records if name.startswith(('lib/domain/','lib/services/'))}
    if any(v==0 for name in critical for v in records[name].values()):
        raise ValueError('Critical domain/auth/storage/process coverage below 100%')
    if not total or covered/total<0.995:raise ValueError('Coverage below 99.5%')
    return records,{'covered':covered,'total':total,'percent':100*covered/total,'changed_scope':'all new handwritten Dart executable lines','critical_files':sorted(critical),'declaration_only':DECLARATIONS,'branch_coverage':'unmeasured'}

if __name__=='__main__':
    records,result=check([Path(p) for p in sys.argv[1:]])
    lines=[]
    for name,values in sorted(records.items()):
        lines+=['SF:'+name]+[f'DA:{n},{v}' for n,v in sorted(values.items())]+['end_of_record']
    (ROOT/'coverage/lcov.info').write_text('\n'.join(lines)+'\n')
    (ROOT/'coverage/result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
