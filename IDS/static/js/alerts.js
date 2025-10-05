 async function fetchAlerts() {
      try {
        const res = await fetch("/alerts.json", { cache: "no-store" });
        if (!res.ok) return;
        const alerts = await res.json();
        const tbody = document.querySelector("#alerts-table tbody");
        if (!tbody) return;

        tbody.innerHTML = ""; // clear
        for (const a of alerts) {
          const tr = document.createElement("tr");
          if (a.is_syn) tr.classList.add("syn");

          const tdTime = document.createElement("td");
          tdTime.textContent = a.timestamp || "-";
          const tdIp = document.createElement("td");
          tdIp.textContent = a.ip || "-";
          const tdMsg = document.createElement("td");
          tdMsg.textContent = a.message || "-";
          const tdStatus = document.createElement("td");
          if (a.is_syn) {
            const span = document.createElement("span");
            span.className = "tag syn";
            span.textContent = "SYN";
            tdStatus.appendChild(span);
          } else {
            const span = document.createElement("span");
            span.className = "small";
            span.textContent = "—";
            tdStatus.appendChild(span);
          }

          tr.appendChild(tdTime);
          tr.appendChild(tdIp);
          tr.appendChild(tdMsg);
          tr.appendChild(tdStatus);
          tbody.appendChild(tr);
        }
      } catch (e) {
        // silent fail; you could add retry/backoff logic
        console.error("Failed to fetch alerts:", e);
      }
    }

    // initial fetch and polling
    fetchAlerts();
    setInterval(fetchAlerts, 3000);
