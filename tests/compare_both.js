"use strict";
let multiHashing = require('../build/Release/multihashing');
let fs = require('fs');
let lineReader = require('readline');

let testsFailed = 0, testsPassed = 0, line_count=0;
let lr = lineReader.createInterface({
     input: fs.createReadStream('cryptonight.txt')
});
lr.on('line', function (line) {
    let line_data = line.split(/ (.+)/);
    line_count += 1;
    multiHashing.cryptonight_async(function(err, result){
        if (line_data[0] !== result.toString('hex')){
            testsFailed += 1;
        } else {
            testsPassed += 1;
        }
        if (result !== multiHashing.cryptonight(Buffer.from(line_data[1]))){
            console.log('The two functions do not agree');
        }
        if (line_count === (testsFailed + testsPassed)){
            if (testsFailed > 0){
                console.log(testsFailed + '/' + (testsPassed + testsFailed) + ' tests failed on: cryptonight_async');
            } else {
                console.log(testsPassed + ' tests passed on: cryptonight_async');
            }
        }
    }, Buffer.from(line_data[1]));
});
