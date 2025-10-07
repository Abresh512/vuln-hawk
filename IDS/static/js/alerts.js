    async function fetchAlerts(){
      try{
        const res = await fetch("/alerts.json",{cache:"no-store"});
        if(!res.ok) return;
        const alerts = await res.json();
        const tbody = document.querySelector("#alerts-table tbody");
        tbody.innerHTML = "";
        for(const a of alerts){
          const tr = document.createElement("tr");
          if(a.is_syn) tr.classList.add("syn");
          tr.innerHTML = `<td>${a.timestamp||"-"}</td><td>${a.ip||"-"}</td><td>${a.message||"-"}</td><td>${a.is_syn?'<span class="tag syn">SYN</span>':'—'}</td>`;
          tbody.appendChild(tr);
        }
      }catch(e){ console.error(e); }
    }

    async function fetchActive(){
      try{
        const res = await fetch("/active.json",{cache:"no-store"});
        if(!res.ok) return;
        const active = await res.json();
        const tbody = document.querySelector("#active-table tbody");
        tbody.innerHTML = "";
        for(const a of active){
          const tr = document.createElement("tr");
          tr.innerHTML = `<td>${a.ip}</td><td>${a.last_seen}</td><td>${a.age_s}</td><td>${a.count}</td>`;
          tbody.appendChild(tr);
        }
      }catch(e){ console.error(e); }
    }

    // poll both endpoints every 3 seconds
    fetchAlerts(); fetchActive();
    setInterval(()=>{ fetchAlerts(); fetchActive(); }, 3000);