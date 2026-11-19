const themeOptions = ["system", "dark", "light"];
let theme = "dark";
try {
	theme = localStorage.getItem("meow-theme") || "dark";
} catch {}
if (!themeOptions.includes(theme)) theme = "dark";
function applyTheme() {
	document.documentElement.dataset.theme = theme;
	for (const button of document.querySelectorAll("[data-theme-toggle]"))
		button.textContent = `Theme: ${theme}`;
}
applyTheme();
for (const button of document.querySelectorAll("[data-theme-toggle]"))
	button.addEventListener("click", () => {
		theme =
			themeOptions[(themeOptions.indexOf(theme) + 1) % themeOptions.length];
		try {
			localStorage.setItem("meow-theme", theme);
		} catch {}
		applyTheme();
	});
