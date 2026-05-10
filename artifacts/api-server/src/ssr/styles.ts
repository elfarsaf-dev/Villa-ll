export const COMMON_HEAD = `
  <meta charset="utf-8"/>
  <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🏡</text></svg>"/>
  <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Serif:ital,wght@0,400;0,700;1,400&family=Plus+Jakarta+Sans:wght@400;500;600&display=swap" rel="stylesheet"/>
`;

export const TAILWIND_COLORS = `
  tailwind.config = {
    darkMode: "class",
    theme: {
      extend: {
        colors: {
          "primary": "#1e3a2f","primary-container": "#2d4f3f","on-primary": "#ffffff",
          "on-primary-container": "#a8c5b5","secondary": "#5c6b5e","secondary-container": "#dde8df",
          "on-secondary": "#ffffff","on-secondary-container": "#3a4d3d","background": "#f8faf8",
          "surface": "#f8faf8","surface-dim": "#d8ddd9","surface-container-lowest": "#ffffff",
          "surface-container-low": "#f2f5f2","surface-container": "#ecefec",
          "surface-container-high": "#e6eae6","surface-container-highest": "#e0e4e0",
          "on-surface": "#191d1a","on-surface-variant": "#404944","outline": "#707973","outline-variant": "#bfc9c1",
        },
        borderRadius: { "DEFAULT": "0.125rem","lg": "0.375rem","xl": "0.5rem","2xl": "0.75rem","full": "9999px" },
        fontFamily: { "serif": ["Noto Serif","Georgia","serif"],"sans": ["Plus Jakarta Sans","sans-serif"] },
      },
    },
  }
`;
