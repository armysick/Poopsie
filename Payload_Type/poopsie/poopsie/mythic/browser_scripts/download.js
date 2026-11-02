function(task, responses){

  // Find the agent_file_id (a UUID) somewhere in `responses`. Older Poopsie
  // put the UUID at responses[0] because completeDownload was the only
  // user_output the task ever emitted. The agent now also emits progress
  // lines like "Starting download: ..." and "Downloaded X/Y chunks (Z%)",
  // so we scan from the END of responses backward for the first value
  // matching the UUID shape. Falls back to responses[0] for safety.
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  function findFileId(resps){
    for(let i = resps.length - 1; i >= 0; i--){
      const r = (resps[i] || "").trim();
      if(uuidRe.test(r)) return r;
    }
    return resps[0];
  }

  if(task.status.includes("error")){
      const combined = responses.reduce( (prev, cur) => {
          return prev + cur;
      }, "");
      return {'plaintext': combined};
  }else if(task.completed){
      if(responses.length > 0){
          try{
              return { "media": [{
                      "filename": `${task.display_params}`,
                      "agent_file_id": findFileId(responses),
                  }]};
          }catch(error){
              const combined = responses.reduce( (prev, cur) => {
                  return prev + cur;
              }, "");
              return {'plaintext': combined};
          }

      }else{
          return {"plaintext": "No data to display..."}
      }

  }else{
      // While downloading, just render the accumulated user_output lines
      // ("Starting download: ...", "Downloaded X/Y chunks (Z%)", ...) as
      // plaintext. The previous JSON.parse(responses[0]) path only worked
      // for a legacy format the agent no longer emits.
      if(responses.length > 0){
          const combined = responses.reduce( (prev, cur) => {
              return prev + cur;
          }, "");
          return {"plaintext": combined};
      }
      return {"plaintext": "No data yet..."}
  }
}