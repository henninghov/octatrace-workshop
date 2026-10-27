// Reuse the pinned firmware artwork renderer; preserve the original compass SVG.
const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const rasterRoot=process.argv[2];
if(!rasterRoot)throw new Error('Supply the existing firmware build/raster directory');
const modulePath=path.join(path.resolve(rasterRoot),'node_modules/@resvg/resvg-js');
if(require(path.join(modulePath,'package.json')).version!=='2.6.2')throw new Error('Renderer pin mismatch');
const {Resvg}=require(modulePath);
const root=path.resolve(__dirname,'..');const source=fs.readFileSync(path.join(root,'assets/branding/compass.svg'));
const hash=crypto.createHash('sha256').update(source).digest('hex');
if(hash!=='e58bda47f3ac032855fed17b0d51aeb0e397a7940d8b2ce8fa7eb19d0b230eb4')throw new Error('Original compass mismatch');
const icons=path.join(root,'macos/Runner/Assets.xcassets/AppIcon.appiconset');
const entries=JSON.parse(fs.readFileSync(path.join(icons,'Contents.json'))).images;
const outputs={};
for(const entry of entries){
 const size=Number.parseFloat(entry.size)*Number.parseFloat(entry.scale);
 const margin=size*.16, width=size-2*margin;
 const svg=`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${size}" height="${size}"><rect width="${size}" height="${size}" rx="${size*.2}" fill="#252525"/><image x="${margin}" y="${margin}" width="${width}" height="${width}" xlink:href="data:image/svg+xml;base64,${source.toString('base64')}"/></svg>`;
 const data=new Resvg(svg).render().asPng();fs.writeFileSync(path.join(icons,entry.filename),data);
 outputs[entry.filename]={pixels:size,sha256:crypto.createHash('sha256').update(data).digest('hex')};
}
fs.writeFileSync(path.join(root,'design/app-icon-manifest.json'),JSON.stringify({source:'assets/branding/compass.svg',source_sha256:hash,renderer:'resvg-js 2.6.2',outputs},null,2)+'\n');
console.log('Rendered original compass into all macOS app-icon slots.');
