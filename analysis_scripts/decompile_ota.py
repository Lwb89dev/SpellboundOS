#!/usr/bin/env python3
"""Run bounded Ghidra analysis on six candidate RISC-V OTA images.

Writes private analysis databases and vendor-derived code only below firmware/.
Use a fresh project directory; existing programs are not overwritten.
"""
import subprocess,pathlib,json,time
import argparse
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ghidra', required=True, help='absolute analyzeHeadless path')
args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
head=str(pathlib.Path(args.ghidra).resolve())
(root/'firmware/ghidra-bulk').mkdir(parents=True,exist_ok=True)
(root/'firmware/decompiled').mkdir(parents=True,exist_ok=True)
targets=[('boot','bootloader-from-0x400.bin','0x80c00000','0x80c0022c'),('recovery','recovery_sign.bin','0x80d00000','0x80d0022c'),('sensor','sensorhub@mhs003_sign.bin','0x80f62000','0x80f6224c'),('factory','fct_test_sign.bin','0x70000000','0x7000022c'),('main','firmware_sign.bin','0x70160000','0x7016022c'),('ramdump','ramdump.bin','0x70000000','0x70000238')]
import os
import zipfile
inputs = root / 'firmware/bulk-inputs'
inputs.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(root/'firmware/bip6-4.6.0.3.zip') as archive:
 for name,image,base,entry in targets:
  member = ('META/ramdump/ramdump_pamir_64m@mhs003.bin' if name == 'ramdump' else
            'META/bootloader_sign.bin' if name == 'boot' else
            'META/'+image if name == 'main' else 'META/extfw/'+image)
  data = archive.read(member)
  if name == 'boot': data = data[0x400:]
  (inputs/image).write_bytes(data)
env=dict(os.environ,GHIDRA_HEADLESS_MAXMEM='6G')
results=[]
for name,image,base,entry in targets:
 start=time.monotonic();out=root/'firmware/decompiled'/name
 cmd=[head,str(root/'firmware/ghidra-bulk'),name,'-import',str(inputs/image),'-loader','BinaryLoader','-loader-baseAddr',base,'-processor','RISCV:LE:32:AndeStar_v5','-cspec','gcc','-scriptPath',str(root/'analysis_scripts'),'-preScript','SeedEntry.java',entry,'-postScript','ExportFunctions.java',str(out),'-analysisTimeoutPerFile',('1800' if name == 'main' else '300'),'-log',str(root/f'firmware/bulk-{name}.log')]
 with open(root/f'firmware/bulk-{name}-stdout.log','w') as log:
  p=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,env=env)
 rows=(out/'functions.tsv').read_text().splitlines()[1:] if (out/'functions.tsv').exists() else []
 result=dict(name=name,image=image,base=base,entry=entry,returncode=p.returncode,seconds=round(time.monotonic()-start,1),functions=len(rows),completed=sum('\tcompleted\t' in x for x in rows))
 results.append(result);(root/'firmware/bulk-summary.json').write_text(json.dumps(results,indent=2));print(json.dumps(result),flush=True)
