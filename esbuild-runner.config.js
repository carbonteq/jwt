const config = {
  type: 'transform',
  esbuild: {
    loader: {
      '.node': 'file',
    },
  },
};

module.exports = config;
