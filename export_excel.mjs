// Excel presentation exporter for a workstation with @oai/artifact-tool available.
// The AWS collector needs neither Node nor this package. CSV is the portable fallback.
import fs from 'node:fs/promises';
import path from 'node:path';
import { Workbook, SpreadsheetFile } from '@oai/artifact-tool';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('Usage: node export_excel.mjs review.json output.xlsx');
const { report, rows } = JSON.parse(await fs.readFile(input, 'utf8'));
if (rows.length > 10000) throw new Error('Split the report into batches of at most 10,000 hosts.');
const wb = Workbook.create();
const review = wb.worksheets.add('Review');
const evidence = wb.worksheets.add('Evidence');
const safe = value => typeof value === 'string' && /^[\s]*[=+@-]/.test(value) ? "'" + value : value;
const end = 9 + Math.max(rows.length, 1);
for (const sheet of [review, evidence]) {
  sheet.showGridLines = false;
  sheet.getRange(`A1:K${end}`).format.font = {name:'Arial', size:10, color:'#1F2937'};
  sheet.getRange(`A1:K${end}`).format.verticalAlignment = 'center';
  sheet.getRange('A2').values = [[sheet === review ? 'PHP patch review' : 'PHP inventory evidence']];
  sheet.getRange('A2').format.font = {size:16, bold:true};
  sheet.getRange('A3').values = [[report.source]];
  sheet.getRange('A3:K3').format.font = {color:'#9A3412', italic:true};
  sheet.getRange('A1:K1').format.rowHeight = 8;
  sheet.freezePanes.freezeRows(9);
}
review.getRange('A5:B7').values = [['Hosts in scope', rows.length], ['Incomplete hosts', null], ['Regional errors', report.coverage_errors.length]];
review.getRange('B6').formulas = [[`=COUNTIF(E10:E${end},"SCAN_INCOMPLETE")`]];
review.getRange('D5').values = [['Decision is review metadata. SSM approval is required separately.']];
review.getRange('D6').values = [['Fix level detected does not verify the serving web workers.']];
review.getRange('D7').values = [['Amber columns: reviewer input. No macros or patch buttons.']];
review.getRange('A9:K9').values = [['Instance ID','Region','OS','PHP installed?','Patch evidence','Next action','Decision','Reviewer','Change ticket','Vendor advisory URL','Restart / health evidence']];
const data = rows.map(r => [r.instance_id,r.region,r.os,r.php,r.assessment,r.action,r.decision,r.reviewer,r.ticket,r.vendor_evidence,r.restart_health_evidence].map(safe));
if (data.length) review.getRange(`A10:K${end}`).values = data;
review.getRange(`G10:K${end}`).format.fill = '#FFF7D6';
review.getRange(`G10:G${end}`).dataValidation = {rule:{type:'list',values:['Pending','Investigate','Patch requested','Exception requested','Verified after change']}};
review.getRange(`E10:E${end}`).conditionalFormats.add('containsText', {text:'INCOMPLETE',format:{fill:'#FEE2E2',font:{color:'#991B1B',bold:true}}});
review.getRange(`G10:G${end}`).conditionalFormats.add('containsText', {text:'Patch requested',format:{fill:'#DBEAFE',font:{color:'#1E40AF'}}});
const widths = [27,16,20,23,35,66,27,24,24,50,50];
for (let c=0;c<widths.length;c++) review.getRangeByIndexes(0,c,end,1).format.columnWidth=widths[c];
review.getRange(`D10:F${end}`).format.wrapText=true;
review.getRange(`A10:K${end}`).format.rowHeight=48;

evidence.getRange('A5').values = [['Account: ' + report.account + '    Scope: ' + report.scope_tag]];
evidence.getRange('A6').values = [['Source: https://www.php.net/archive/2026.php#2026-10-21-5']];
evidence.getRange('A7').values = [['Scope: CVE-2026-109618 and CVE-2026-109619. Review the separate 23 October session-upload guidance.']];
evidence.getRange('A9:H9').values = [['Instance ID','Scan status','Package versions','Binary versions','SSM command ID','Collected at (UTC)','Collector errors','Scope limitations']];
const proof = rows.map((r, i) => [r.instance_id, r.scan, r.versions || '(none observed)', r.binaries || '(none observed)',r.command_id,
  new Date(report.generated_at), (report.hosts[i].inventory?.errors || []).join('; '), 'Host packages and known paths only. Containers, custom builds and loaded workers need separate checks.'].map(safe));
if(proof.length) evidence.getRange(`A10:H${end}`).values=proof;
evidence.getRange(`F10:F${end}`).setNumberFormat('yyyy-mm-dd hh:mm');
for (const [i,width] of [27,28,65,55,42,23,36,62].entries()) evidence.getRangeByIndexes(0,i,end,1).format.columnWidth=width;
evidence.getRange(`A10:H${end}`).format.wrapText=true;
evidence.getRange(`A10:H${end}`).format.rowHeight=56;
for(const [sheet,last,name] of [[review,'K','PHPReview'],[evidence,'H','PHPEvidence']]) {
  sheet.getRange(`A9:${last}9`).format={fill:'#243B53',font:{bold:true,color:'#FFFFFF'},rowHeight:30,wrapText:true,horizontalAlignment:'center'};
  sheet.tables.add(`A9:${last}${end}`,true,name);
}
wb.recalculate();
console.log((await wb.inspect({kind:'region',sheetId:'Review',range:'A5:B7',maxChars:1500,include:'values,formulas'})).ndjson);
console.log((await wb.inspect({kind:'match',searchTerm:'#REF!|#DIV/0!|#VALUE!|#NAME\\?|#NUM!|#SPILL!',options:{useRegex:true,maxResults:20},maxChars:1500})).ndjson);
await fs.mkdir(path.dirname(output),{recursive:true});
const book=await SpreadsheetFile.exportXlsx(wb); await book.save(output); await fs.chmod(output,0o600);
if(process.env.RENDER_PREVIEW === '1') {
  for(const [name,range,label] of [['Review',`A1:F${end}`,'review'],['Review',`G8:K${end}`,'decisions'],['Evidence',`A8:D${end}`,'packages'],['Evidence',`E8:H${end}`,'evidence']]) {
    const png=await wb.render({sheetName:name,range,scale:1.3,format:'png'});
    await fs.writeFile(path.join(path.dirname(output),label+'.png'),new Uint8Array(await png.arrayBuffer()));
  }
}
console.log(output);
