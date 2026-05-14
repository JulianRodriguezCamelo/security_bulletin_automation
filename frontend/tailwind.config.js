/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50:  '#fdf2f5',
          100: '#fbe8ed',
          200: '#f5c6d3',
          300: '#ead8de',
          400: '#e0cdd3',
          500: '#C1294A',
          600: '#a82240',
          700: '#8B1A33',
          900: '#4A0E24',
          950: '#360A1A',
        },
        bg:      '#F7F0EC',
        surface: '#FFFFFF',
      },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
      boxShadow: {
        card: '0 2px 12px rgba(74,14,36,0.08)',
        sm:   '0 1px 4px rgba(74,14,36,0.07)',
      },
    },
  },
  plugins: [],
}

