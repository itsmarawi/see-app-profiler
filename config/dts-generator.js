const artifacts = require('./artifacts');

/** @type import('dts-bundle-generator/config-schema').OutputOptions */
const commonOutputParams = {
    inlineDeclareGlobals: false,
    sortNodes: true,
};

/** @type import('dts-bundle-generator/config-schema').BundlerConfig */
const config = {
    compilationOptions: {
        preferredConfigPath: '../tsconfig.dts-generator.json',
    },
    entries: [
        {
            filePath: '../src/profiler.ts',
            outFile: '../dist/'+ artifacts.profiler + '.d.ts',     
            output: commonOutputParams,
        },
        
    ],
};
module.exports = config;