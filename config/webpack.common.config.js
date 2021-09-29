var helpers = require('./helpers');
var path = require('path');
const artifacts = require('./artifacts');


module.exports = {
    entry: {
        [artifacts.profiler]: './src/index.ts',
    },
    resolve: {
        extensions: ['.ts', '.js'],
        
        modules: [helpers('src'), helpers('node_modules')],

        alias: {
            "@see-app": path.resolve("./src")
        }
    },
    module: {
        rules: [{
            test: /\.tsx?$/,            
            exclude: /node_modules/,
            use: [{
                loader: 'ts-loader',
                options: {
                    appendTsSuffixTo: [/\.vue$/],
                },
            }]
        }]
    },
    devServer: {
        historyApiFallback: true,
        noInfo: false
    },
    performance: {
        hints: false
    },
    devtool: '#eval-source-map'
};
