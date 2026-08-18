(function () {
  "use strict";

  var router = globalThis.MacoScope && globalThis.MacoScope.router;
  if (!router) return;

  var nav = document.getElementById("appNav");
  var pages = {
    live: document.getElementById("liveView"),
    catalog: document.getElementById("catalogView"),
    objective: document.getElementById("objectiveView"),
  };

  function show(page) {
    Object.keys(pages).forEach(function (name) {
      var node = pages[name];
      if (!node) return;
      var active = name === page;
      node.hidden = !active;
      node.setAttribute("aria-hidden", active ? "false" : "true");
    });
    if (nav) {
      nav.querySelectorAll("[data-page]").forEach(function (link) {
        var active = link.getAttribute("data-page") === page;
        link.setAttribute("aria-current", active ? "page" : "false");
        link.classList.toggle("is-active", active);
      });
    }
    document.body.dataset.macoPage = page;
    document.dispatchEvent(
      new CustomEvent("maco-scope-page", { detail: { page: page } }),
    );
  }

  function syncFromLocation() {
    show(router.pageFromLocation(window.location));
  }

  if (nav) {
    nav.querySelectorAll("[data-page]").forEach(function (link) {
      link.addEventListener("click", function (event) {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        var page = link.getAttribute("data-page");
        if (page === "live" && window.location.search) {
          window.location.hash = router.hrefFor("live").slice(1);
        } else {
          window.location.hash = router.hrefFor(page).slice(1);
        }
        syncFromLocation();
      });
    });
  }

  window.addEventListener("hashchange", syncFromLocation);
  if (!window.location.hash) {
    window.location.hash = "/live";
  }
  syncFromLocation();
})();
