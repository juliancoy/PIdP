import {readFileSync} from 'node:fs'
export const userModel=JSON.parse(readFileSync(new URL('./model.json',import.meta.url),'utf8'))

export function assessOutcome(task, evidence=[]) {
 const missing=task.requiredEvidence.filter(item=>!evidence.includes(item))
 return {status:missing.length?'destination-unverified':'verified',missing}
}

// Observe rendered affordances before the existing clickthrough exercises actions.
// Outcome evidence must come from assertions in that journey, never from a URL alone.
export async function reviewUserTask(page, taskId, parameters, evidence=[]) {
 const task=userModel.tasks.find(item=>item.id===taskId)
 if(!task)throw Error(`Unknown user task: ${taskId}`)
 const report={task:task.id,persona:task.persona,goal:task.success,checks:[],outcome:assessOutcome(task,evidence),humanReview:task.humanPrinciples.map(id=>({id,status:'pending'}))}
 if(!task.action){report.status='not-assessed';return report}
 const expected=task.action.destination.replace(/\{(\w+)\}/g,(_,key)=>{
  if(!parameters[key])throw Error(`Missing task parameter: ${key}`)
  return encodeURIComponent(parameters[key])
 })
 const control=page.locator(task.scope).getByRole(task.action.role,{name:task.action.name,exact:true})
 const count=await control.count()
 report.checks.push({id:'unambiguous-action',passed:count===1,count})
 if(count===1){
  report.checks.push({id:'visible-action',passed:await control.isVisible()})
  report.checks.push({id:'enabled-action',passed:await control.isEnabled()})
  const href=await control.getAttribute('href'),actual=new URL(href||'',page.url()),origin=new URL(page.url()).origin
  report.checks.push({id:'expected-destination',passed:actual.origin===origin&&actual.pathname===expected&&!actual.search&&!actual.hash,expected,observed:actual.origin===origin?actual.pathname:'external-origin'})
 }
 report.status=report.checks.every(check=>check.passed)?'affordance-verified':'failed'
 return report
}
