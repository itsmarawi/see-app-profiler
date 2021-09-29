const webpack = require('webpack');
const webpackMerge = require('webpack-merge');
const commonConfig = require('./webpack.common.config.js');
const helpers = require('./helpers.js');
const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;
 
const ENV = process.env.NODE_ENV;

module.exports = webpackMerge.merge(commonConfig, {
  devtool: 'source-map',
  mode: "development",

  output: {
    path: helpers('dist'),
    filename: '[name].js',
    chunkFilename: '[id].chunk.js',
    libraryTarget: "commonjs"
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env': {
        'ENV': JSON.stringify(ENV)
      }
    }),
    new BundleAnalyzerPlugin({
      analyzerMode: "none"
    })
  ]
});

