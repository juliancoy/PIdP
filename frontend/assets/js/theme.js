(function () {
    var storageKey = "pidp-theme-mode";
    var root = document.documentElement;
    var select = document.getElementById("theme-mode");
    var media = window.matchMedia("(prefers-color-scheme: dark)");

    function resolveTheme(mode) {
        if (mode === "dark") {
            return "dark";
        }
        if (mode === "light") {
            return "light";
        }
        if (mode === "auto") {
            var hour = new Date().getHours();
            return hour < 7 || hour >= 19 ? "dark" : "light";
        }
        return media.matches ? "dark" : "light";
    }

    function applyTheme(mode) {
        var resolved = resolveTheme(mode);
        root.dataset.themeMode = mode;
        root.dataset.theme = resolved;
        if (select) {
            select.value = mode;
        }
    }

    var currentMode = localStorage.getItem(storageKey) || root.dataset.themeMode || "system";
    applyTheme(currentMode);

    if (select) {
        select.addEventListener("change", function (event) {
            var nextMode = event.target.value || "system";
            localStorage.setItem(storageKey, nextMode);
            applyTheme(nextMode);
        });
    }

    media.addEventListener("change", function () {
        var mode = localStorage.getItem(storageKey) || "system";
        if (mode === "system") {
            applyTheme(mode);
        }
    });

    window.setInterval(function () {
        var mode = localStorage.getItem(storageKey) || "system";
        if (mode === "auto") {
            applyTheme(mode);
        }
    }, 60000);
}());
