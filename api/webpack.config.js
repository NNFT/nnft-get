module.exports = {
  entry: "./src/api-get-nnft.js",
  output: {
    library: "sls",
    umdNamedDefine: true,
    filename: "API-GET-NNFT.js",
    path: __dirname + "/dist",
    libraryTarget: 'umd',
    globalObject: 'this'

  },
  mode: "production",
  devtool: "source-map",
  resolve: {
    extensions: [".ts", ".tsx", ".js", ".json", ".css"]
  },

  module: {
    rules: [
    ]
  },
 resolve: {
    fallback: {
      "crypto": require.resolve("crypto-browserify"),
    },
  },
 plugins: [
 ],
  node: {
  }
};

