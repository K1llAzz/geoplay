document.querySelectorAll(".dropdown").forEach(drop=>{
  const btn = drop.querySelector(".dropdown-btn");
  const menu = drop.querySelector(".dropdown-menu");
  const input = drop.querySelector("input[type=hidden]");

  btn.onclick = e=>{
    e.stopPropagation();
    document.querySelectorAll(".dropdown").forEach(d=>{
      if(d!==drop) d.classList.remove("open");
    });
    drop.classList.toggle("open");
  };

  menu.querySelectorAll(".dropdown-item").forEach(item=>{
    item.onclick = ()=>{
      btn.querySelector("span").innerHTML = item.innerHTML;
      input.value = item.dataset.value;
      drop.classList.remove("open");
      input.dispatchEvent(new Event("change"));
    };
  });
});

document.addEventListener("click",()=>{
  document.querySelectorAll(".dropdown").forEach(d=>d.classList.remove("open"));
});
sort.onchange = loadVideos;
