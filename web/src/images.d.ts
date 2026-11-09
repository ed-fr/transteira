// Images imported by the components: Vite copies them to dist/assets/ (fingerprinted name,
// never inlined: assetsInlineLimit 0) and the import gives their URL.
declare module '*.png' {
  const url: string;
  export default url;
}
