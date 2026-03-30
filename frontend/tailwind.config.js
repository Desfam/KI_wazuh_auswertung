/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0d1b1e',
        shell: '#f4efe7',
        ember: '#cb5c32',
        brass: '#b68a48',
        pine: '#26443c',
        signal: '#a32020',
        slate: '#475a5f'
      },
      boxShadow: {
        panel: '0 18px 50px rgba(13, 27, 30, 0.16)'
      },
      backgroundImage: {
        grid: 'linear-gradient(rgba(13, 27, 30, 0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(13, 27, 30, 0.06) 1px, transparent 1px)'
      }
    }
  },
  plugins: []
};
