"use strict";
/*! DO NOT INSTRUMENT */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const sourcemaps_1 = require("./sourcemaps");
const IGNORED_COMMANDS = [
    "npm", "npm-cli.js",
    "grunt", "rollup", "browserify", "webpack", "terser",
    "rimraf",
    "eslint", "tslint", "jslint", "jshint", "stylelint", "prettier", "xo", "standard",
    "tsc", "tsd",
    "nyc",
];
const log = process.stdout.isTTY ? console.log.bind(console) : () => { };
const cwd = process.cwd();
const JELLY_BASEDIR = process.env.JELLY_BASEDIR || cwd;
const jellybin = process.env.JELLY_BIN;
if (!jellybin) {
    console.error('Error: Environment variable JELLY_BIN not set, aborting');
    process.exit(-1);
}
const node = `${jellybin}/node`;
const child_process = require("child_process");
for (const fun of ["spawn", "spawnSync"]) {
    const real = child_process[fun];
    child_process[fun] = function () {
        const env = arguments[2]?.env || process.env;
        const opts = { ...arguments[2],
            env: { ...env,
                PATH: `${jellybin}${env.PATH ? `:${env.PATH}` : ""}`,
                NODE: node,
                npm_node_execpath: node,
                JELLY_BASEDIR,
            } };
        return real.call(this, arguments[0], arguments[1], opts);
    };
}
const cmd = process.argv[6];
for (const s of IGNORED_COMMANDS)
    if (cmd.endsWith(`/${s}`)) {
        log(`jelly: Skipping instrumentation of ${cmd}`);
        return;
    }
const outfile = process.env.JELLY_OUT + "-" + process.pid;
const call_file_source_trace_file = process.env.CALL_FILE + "/call_file_source-" + process.pid
const eval_trace_file = process.env.CALL_FILE + "/eval_trace-" + process.pid

if (!("JELLY_OUT" in process.env)) {
    console.error('Error: Environment variable JELLY_OUT not set, aborting');
    process.exit(-1);
}
const util_1 = require("../misc/util");
const sources_1 = require("./sources");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
try {
    const jestDetector = /\/node_modules\/(?:jest(?:-cli)?\/bin\/jest\.js|jest-ci\/bin\.js)$/;
    if (cmd.indexOf("jest") !== -1 && jestDetector.test(fs_1.default.realpathSync(cmd)))
        process.argv.splice(7, 0, "--runInBand");
}
catch (e) { }
log(`jelly: Running instrumented program: node ${process.argv.slice(6).join(" ")} (process ${process.pid})`);
var FunType;
(function (FunType) {
    FunType[FunType["App"] = 0] = "App";
    FunType[FunType["Lib"] = 1] = "Lib";
    FunType[FunType["Test"] = 2] = "Test";
})(FunType || (FunType = {}));
const fileIds = new Map();
const files = [];
const ignoredFiles = new Set(["structured-stack", "evalmachine.<anonymous>"]);
const call2fun = new Map();
const callLocations = new Map();
const funLocStack = Array();
const inAppStack = Array();
let enterScriptLocation = undefined;
const binds = new WeakMap();
const pendingCalls = new WeakMap();
const funIids = new WeakMap();
const iidToInfo = new Map();
const call2FileSource = Array()
const eval_trace = Array()
function addCallEdge(call, callerInfo, callee) {
    (callerInfo.calls ??= new Set()).add(callee);
    if (call) {
        let cs = call2fun.get(call);
        if (!cs) {
            cs = new Set;
            try {
                callLocations.set(call, so2loc(J$.iidToSourceObject(call)));
                call2fun.set(call, cs);
            }
            catch (e) {
                log(`Source mapping error: ${e}, for ${JSON.stringify(J$.iidToSourceObject(call))}`);
            }
        }
        cs.add(callee);
    }
}
function registerCall(call, callerInfo, callee) {
    let bound;
    while ((bound = binds.get(callee)) !== undefined)
        callee = bound;
    const calleeIid = funIids.get(callee);
    if (calleeIid === undefined)
        (0, util_1.mapArrayAdd)(callee, [callerInfo, call], pendingCalls);
    else {
        const calleeInfo = iidToInfo.get(calleeIid);
        if (calleeInfo.type !== FunType.Test && !calleeInfo.ignored)
            addCallEdge(call, callerInfo, calleeIid);
    }
}
function so2loc(s) {
    let fid = fileIds.get(s.name);
    s = (0, sourcemaps_1.getSourceObject)(s);
    if (fid === undefined) {
        fid = files.length;
        files.push(s.name);
        fileIds.set(s.name, fid);
    }
    return `${fid}:${s.loc.start.line}:${s.loc.start.column}:${s.loc.end.line}:${s.loc.end.column + 1}`;
}
const pathToFunType = (() => {
    const cache = new Map();
    return (path) => {
        let typ = cache.get(path);
        if (typ !== undefined)
            return typ;
        typ = path === "<builtin>" ? FunType.Lib :
            path.startsWith("/") || path.includes("node_modules/") ?
                ((0, sources_1.isPathInTestPackage)(path) ? FunType.Test : FunType.Lib)
                : FunType.App;
        cache.set(path, typ);
        return typ;
    };
})();
J$.addAnalysis({
    invokeFunPre: function (iid, f, _base, _args, _isConstructor, _isMethod, _functionIid, _functionSid) {
        call2FileSource.push(`Call:${J$.iidToLocation(iid)}`)
        const callerInApp = inAppStack.length > 0 && inAppStack[inAppStack.length - 1];
        if (callerInApp && typeof f === "function") {
            const callerIid = funLocStack[funLocStack.length - 1];
            const callerInfo = iidToInfo.get(callerIid);
            if (!callerInfo.ignored)
                registerCall(iid, callerInfo, f);
        }
    },
    functionEnter: function (iid, func, _receiver, _args) {
        funIids.set(func, iid);
        let info = iidToInfo.get(iid);
        if (info === undefined) {
            const so = J$.iidToSourceObject(iid);
            info = {
                type: pathToFunType(so.name),
                ignored: ("eval" in so) || ignoredFiles.has(so.name),
                loc: enterScriptLocation ?? so,
                observedAsApp: false,
            };
            iidToInfo.set(iid, info);
        }
        let calleeInApp;
        if (inAppStack.length === 0)
            calleeInApp = info.type === FunType.App && !("eval" in info.loc);
        else {
            const callerInApp = inAppStack[inAppStack.length - 1];
            if (callerInApp)
                calleeInApp = info.type !== FunType.Test;
            else
                calleeInApp = info.type === FunType.App;
        }
        inAppStack.push(calleeInApp);
        info.observedAsApp ||= calleeInApp;
        const pCalls = pendingCalls.get(func);
        if (pCalls !== undefined) {
            pendingCalls.delete(func);
            if (calleeInApp && !info.ignored)
                for (const [caller, callIid] of pCalls)
                    addCallEdge(callIid, caller, iid);
        }
        funLocStack.push(iid);
        enterScriptLocation = undefined;
    },
    functionExit: function (_iid, _returnVal, _wrappedExceptionVal) {
        funLocStack.pop();
        inAppStack.pop();
    },
    newSource: function (sourceInfo, source) {
        if ("eval" in sourceInfo)
            return;
        try {
            const fp = sourceInfo.name.startsWith("file://") ? sourceInfo.name.substring("file://".length) : sourceInfo.name, absfp = path_1.default.isAbsolute(fp) ? fp : path_1.default.join(cwd, fp);
            const diskSource = fs_1.default.readFileSync(absfp, "utf-8");
            if (diskSource !== source && !(0, sources_1.isSourceSimplyWrapped)(diskSource, source)) {
                log(`jelly: the source for ${sourceInfo.name} does not match the on-disk content, trying to find source mapping`);
                const m = (0, sourcemaps_1.decodeAndSetSourceMap)(source, sourceInfo.name);
                if (!m) {
                    log(`jelly: the source mapping for ${sourceInfo.name} can't find - ignoring`);
                    ignoredFiles.add(sourceInfo.name);
                }
            }
        }
        catch (error) {
            if (error.code !== "ENOENT")
                throw error;
        }
        // 计算源代码的行列信息
        let endLine = 1, last = 0;
        for (let i = 0; i < source.length; i++) {
            if (source[i] === '\n') {
                endLine++;
                last = i + 1;
            }
        }
        const endColumn = source.length - last;
        enterScriptLocation = {
            name: sourceInfo.name,
            loc: {
                start: { line: 1, column: 1 },
                end: { line: endLine, column: endColumn }
            }
        };
        call2FileSource.push(`Source:${sourceInfo.name}:1:1:${endLine}:${endColumn + 1}`);
    },
    builtinEnter(name, f, dis, args) {
        const pCalls = pendingCalls.get(f);
        if (pCalls !== undefined) {
            pendingCalls.delete(f);
            switch (name) {
                case "Function.prototype.call":
                case "Function.prototype.apply": {
                    if (typeof dis === "function") {
                        if (pCalls.length === 1) {
                            const [callerInfo, iid] = pCalls[0];
                            registerCall(iid, callerInfo, dis);
                        }
                        else
                            for (const [callerInfo, iid] of pCalls)
                                registerCall(iid, callerInfo, dis);
                    }
                }
            }
        }
    },
    builtinExit(name, f, dis, args, returnVal, exceptionVal) {
        if (name === "Function.prototype.bind" && typeof returnVal === "function")
            binds.set(returnVal, dis);
    },
    evalPre(iid, str){
        eval_trace.push({"Call":`${J$.iidToLocation(iid)}`, "Arg": str})
    },
}, (source) => {
    if (source.internal && !source.name.startsWith("file://"))
        return false;
    const excludedPacakges = ["node_modules/ts-node/",
        "node_modules/@cspotcode/source-map-support/",
        "node_modules/@jridgewell/resolve-uri/",
        "node_modules/@jridgewell/sourcemap-codec/",
        "node_modules/tslib/",
        "node_modules/typescript/",
        "node_modules/source-map",
        "node_modules/source-map-support",
        "node_modules/jest-cli/",
        "node_modules/@jest/",
        "node_modules/ts-jest/",
        "node_modules/jest-"
    ];
    for (const pattern of excludedPacakges) {
        if (source.name.includes(pattern))
            return false;
    }
    return true;
});
process.on('exit', () => {
    const outputFunctions = [];
    for (const [iid, info] of iidToInfo)
        if (!info.ignored && info.observedAsApp)
            try {
                outputFunctions.push([iid, so2loc(info.loc)]);
            }
            catch (e) {
                log(`Source mapping error: ${e}, for ${JSON.stringify(info.loc)}`);
            }
    if (outputFunctions.length === 0) {
        log(`jelly: No relevant functions detected for process ${process.pid}, skipping file write`);
        return;
    }
    function formatPath(fp) {
        fp = fp.startsWith("file://") ? fp.substring("file://".length) : path_1.default.resolve(cwd, fp);
        return JSON.stringify(path_1.default.relative(JELLY_BASEDIR, fp));
    }
    const fd = fs_1.default.openSync(outfile, "w");
    fs_1.default.writeSync(fd, `{\n "entries": [${formatPath(process.argv[1])}],\n`);
    fs_1.default.writeSync(fd, ` "time": "${new Date().toUTCString()}",\n`);
    fs_1.default.writeSync(fd, ` "files": [`);
    let first = true;
    for (const file of files) {
        fs_1.default.writeSync(fd, `${first ? "" : ","}\n  ${formatPath(file)}`);
        first = false;
    }
    fs_1.default.writeSync(fd, `\n ],\n "functions": {`);
    first = true;
    for (const [iid, loc] of outputFunctions) {
        fs_1.default.writeSync(fd, `${first ? "" : ","}\n  "${iid}": ${JSON.stringify(loc)}`);
        first = false;
    }
    fs_1.default.writeSync(fd, `\n },\n "calls": {`);
    first = true;
    for (const [iid, loc] of callLocations) {
        fs_1.default.writeSync(fd, `${first ? "" : ","}\n  "${iid}": ${JSON.stringify(loc)}`);
        first = false;
    }
    fs_1.default.writeSync(fd, `\n },\n "fun2fun": [`);
    first = true;
    for (const [callerFun, info] of iidToInfo)
        for (const callee of info.calls ?? []) {
            fs_1.default.writeSync(fd, `${first ? "\n  " : ", "}[${callerFun}, ${callee}]`);
            first = false;
        }
    fs_1.default.writeSync(fd, `${first ? "" : "\n "}],\n "call2fun": [`);
    first = true;
    for (const [call, callees] of call2fun)
        for (const callee of callees) {
            fs_1.default.writeSync(fd, `${first ? "\n  " : ", "}[${call}, ${callee}]`);
            first = false;
        }
    fs_1.default.writeSync(fd, `${first ? "" : "\n "}]\n}\n`);
    fs_1.default.closeSync(fd);

    const fd_2 = fs_1.default.openSync(call_file_source_trace_file, "w");
    const json_data = JSON.stringify(call2FileSource, null, 2)
    fs_1.default.writeSync(fd_2, json_data)
    fs_1.default.closeSync(fd_2)

    const fd_3 = fs_1.default.openSync(eval_trace_file, "w");
    const eval_json_data = JSON.stringify(eval_trace, null, 2)
    fs_1.default.writeSync(fd_3, eval_json_data)
    fs_1.default.closeSync(fd_3)
});
//# sourceMappingURL=dyn.js.map