#!/usr/bin/env node
// Build reviewed local repositories without resolving unpublished URLCode peers from a registry.
import {parseArgs} from 'node:util';
import {spawnSync} from 'node:child_process';
import {realpath,mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
const {values}=parseArgs({options:{core:{type:'string'},auth:{type:'string'},admin:{type:'string'},out:{type:'string'},'core-revision':{type:'string'},offline:{type:'boolean'},'skip-install':{type:'boolean'},help:{type:'boolean'}}});
if(values.help){console.log('node scripts/pack-sources.mjs --core PATH --auth PATH [--admin PATH] --core-revision REVIEWED_COMMIT_SHA --out NEW_DIRECTORY [--offline] [--skip-install]');process.exit(0);}
function run(binary,args,cwd,capture=false){const result=spawnSync(binary,args,{cwd,encoding:'utf8',stdio:capture?'pipe':'inherit',shell:false,maxBuffer:4*1024*1024});if(result.error||result.status!==0)throw new Error(`${binary} ${args[0]} failed`);return capture?result.stdout.trim():'';}
try{
 if(!values.core||!values.auth||!values.out||!/^[a-f0-9]{40}$/.test(values['core-revision']??''))throw new Error('Provide source paths, new output directory and exact reviewed core commit');
 const core=await realpath(values.core),auth=await realpath(values.auth),admin=values.admin?await realpath(values.admin):undefined;
 const sources=[core,auth,...(admin?[admin]:[])];if(new Set(sources).size!==sources.length)throw new Error('Source repositories must be distinct');
 const revision=run('git',['rev-parse','HEAD'],core,true);if(revision!==values['core-revision'])throw new Error('Core does not match reviewed revision');
 for(const source of sources)if(run('git',['status','--porcelain','--untracked-files=normal'],source,true))throw new Error('Commit reviewed source changes before creating reproducible packages');
 const metadata=JSON.parse(await readFile(join(core,'package.json'),'utf8'));if(!metadata.exports?.['./extensions'])throw new Error('Core lacks the PR59 extension contract');
 const output=resolve(values.out);await mkdir(output,{mode:0o700});const npm=process.platform==='win32'?'npm.cmd':'npm',offline=values.offline?['--offline']:[];
 const packages=[];
 async function build(source,peers=[]){
  if(!values['skip-install'])run(npm,['ci','--ignore-scripts','--legacy-peer-deps',...offline],source);
  if(peers.length)run(npm,['install','--no-save','--package-lock=false','--ignore-scripts',...offline,...peers],source);
  run(npm,['run','typecheck'],source);run(npm,['run','build'],source);
  const packed=JSON.parse(run(npm,['pack','--ignore-scripts','--json','--pack-destination',output],source,true));if(packed.length!==1)throw new Error('Unexpected package output');
  const record=packed[0];packages.push({name:record.name,version:record.version,filename:record.filename,integrity:record.integrity,revision:run('git',['rev-parse','HEAD'],source,true)});return join(output,record.filename);
 }
 const coreTar=await build(core),authTar=await build(auth,[coreTar]);if(admin)await build(admin,[coreTar,authTar]);
 await writeFile(join(output,'source-manifest.json'),JSON.stringify({schemaVersion:1,packages},null,2)+'\n',{flag:'wx',mode:0o600});
 console.log('Local source packages built. Review source-manifest.json; nothing was published.');
}catch(error){console.error(error instanceof Error?error.message:'Source packaging failed');process.exitCode=1;}
