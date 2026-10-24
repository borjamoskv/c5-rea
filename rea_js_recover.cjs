/* Generic AST recovery tool. Babel is an explicit build-tool dependency.
 * Only audited pure string-table bootstrap code is evaluated. The application
 * entry point, imports and module factories are never executed by this tool.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const {createRequire} = require('node:module');
const [input, output, reportFile, toolchain] = process.argv.slice(2);
const dependency = createRequire(path.join(path.resolve(toolchain), 'package.json'));
const parser = dependency('@babel/parser');
const generate = dependency('@babel/generator').default;
const t = dependency('@babel/types');
const hash = s => crypto.createHash('sha256').update(s).digest('hex');

function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  if (typeof node.type === 'string') visit(node);
  for (const key of t.VISITOR_KEYS[node.type] || []) {
    const value = node[key];
    if (Array.isArray(value)) value.forEach(v => walk(v, visit));
    else walk(value, visit);
  }
}

function flatExpressions(statement) {
  if (!t.isExpressionStatement(statement)) return [];
  return t.isSequenceExpression(statement.expression) ? statement.expression.expressions : [statement.expression];
}

function pureBootstrap(nodes) {
  const allowed = new Set(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression',
    'Identifier','BlockStatement','VariableDeclaration','VariableDeclarator','ArrayExpression',
    'StringLiteral','NumericLiteral','BooleanLiteral','NullLiteral','ReturnStatement',
    'ExpressionStatement','AssignmentExpression','SequenceExpression','CallExpression',
    'MemberExpression','BinaryExpression','LogicalExpression','UnaryExpression',
    'WhileStatement','TryStatement','CatchClause','BreakStatement','IfStatement',
    'EmptyStatement','UpdateExpression','ConditionalExpression']);
  const bound = new Set(['parseInt']);
  let valid = true;
  nodes.forEach(node => walk(node, n => {
    if (t.isFunction(n)) {
      if (n.id) bound.add(n.id.name);
      for (const p of n.params) {
        if (!t.isIdentifier(p)) valid = false;
        else bound.add(p.name);
      }
    }
    if (t.isVariableDeclarator(n)) {
      if (!t.isIdentifier(n.id)) valid = false;
      else bound.add(n.id.name);
    }
    if (t.isCatchClause(n) && n.param) {
      if (!t.isIdentifier(n.param)) valid = false;
      else bound.add(n.param.name);
    }
  }));
  nodes.forEach(node => walk(node, n => {
    if (!allowed.has(n.type)) valid = false;
    if (t.isIdentifier(n) && !bound.has(n.name) && !['push','shift','unshift','pop'].includes(n.name)) valid = false;
    if (t.isMemberExpression(n)) {
      if (!n.computed && (!t.isIdentifier(n.property) || !['push','shift','unshift','pop'].includes(n.property.name))) valid = false;
      // Computed access may index the literal table, but cannot look up a
      // host property or constructor through a string supplied by the bundle.
      if (n.computed && !(t.isIdentifier(n.property) || t.isNumericLiteral(n.property) || t.isBinaryExpression(n.property) ||
          (t.isStringLiteral(n.property) && ['push','shift','unshift','pop'].includes(n.property.value)))) valid = false;
    }
    if (t.isCallExpression(n) && !(t.isIdentifier(n.callee) || t.isFunction(n.callee) ||
        (t.isMemberExpression(n.callee) && ['push','shift','unshift','pop'].includes(
          n.callee.computed ? n.callee.property.value : n.callee.property.name)))) valid = false;
  }));
  return valid;
}

function detectBootstrap(program) {
  const functions = program.body.filter(n => t.isFunctionDeclaration(n)).slice(0, 4);
  for (const table of functions) {
    let literalArray = false;
    walk(table, n => {
      if (t.isArrayExpression(n) && n.elements.length > 16 && n.elements.every(e => t.isStringLiteral(e))) literalArray = true;
    });
    if (!literalArray) continue;
    for (const decoder of functions) {
      if (decoder === table) continue;
      let referencesTable = false;
      walk(decoder, n => { if (t.isCallExpression(n) && t.isIdentifier(n.callee, {name: table.id.name})) referencesTable = true; });
      if (!referencesTable) continue;
      for (const statement of program.body.slice(0, 6)) {
        for (const rotate of flatExpressions(statement)) {
          if (!t.isCallExpression(rotate) || !t.isFunction(rotate.callee) ||
              !t.isIdentifier(rotate.arguments[0], {name: table.id.name}) ||
              !t.isNumericLiteral(rotate.arguments[1]) || rotate.arguments.length !== 2) continue;
          const nodes = [table, decoder, t.expressionStatement(rotate)];
          const prefix=program.body.slice(0,program.body.indexOf(statement));
          if (prefix.every(n=>n===table || n===decoder || t.isEmptyStatement(n)) && pureBootstrap(nodes))
            return {nodes, table, decoder, rotate};
        }
      }
    }
  }
  return null;
}

// Conservative lexical analysis: block-local declarations mask the name for
// the entire function. This can miss optimizations, but never broadens an
// alias beyond the scope in which it was declared. Only unique aliases in the
// direct function body are eligible. No Babel NodePath/scope graph is retained.
function readOnlyLiteralEval(n) {
  if (n.arguments.length!==1 || !t.isStringLiteral(n.arguments[0])) return false;
  try {
    const body=parser.parse(n.arguments[0].value,{sourceType:'script'}).program.body;
    return body.every(s=>t.isEmptyStatement(s) || (t.isExpressionStatement(s) &&
      (t.isIdentifier(s.expression) || t.isStringLiteral(s.expression) || t.isNumericLiteral(s.expression))));
  } catch { return false; }
}

function analyzeScopes(ast) {
  const scopes = new WeakMap();
  const root = {parent:null, bindings:new Map(), unsafe:false};
  scopes.set(ast.program,root);
  function names(n, visit) {
    if (t.isVariableDeclaration(n)) n.declarations.forEach(d=>names(d.id,visit));
    else if (t.isIdentifier(n)) visit(n.name);
    else if (t.isRestElement(n)) names(n.argument,visit);
    else if (t.isAssignmentPattern(n)) names(n.left,visit);
    else if (t.isArrayPattern(n)) n.elements.forEach(e => e && names(e,visit));
    else if (t.isObjectPattern(n)) n.properties.forEach(p => names(t.isRestElement(p) ? p.argument : p.value,visit));
  }
  function declare(scope,name,init=null,eligible=false,node=null) {
    if (scope.bindings.has(name)) { scope.bindings.get(name).eligible=false; return; }
    scope.bindings.set(name,{scope,init,eligible,node,mutable:false});
  }
  function scan(n,scope,body,depth=0) {
    if (!n) return;
    if (t.isFunction(n)) {
      if (t.isFunctionDeclaration(n) && n.id) declare(scope,n.id.name,null,false,n);
      const inner = {parent:scope,bindings:new Map(),unsafe:false}; scopes.set(n,inner);
      if (n.id) declare(inner,n.id.name);
      n.params.forEach(p => names(p,name=>declare(inner,name)));
      scan(n.body,inner,n.body,0); return;
    }
    if (t.isVariableDeclaration(n)) for (const d of n.declarations)
      names(d.id,name=>declare(scope,name,d.init,t.isIdentifier(d.id) && depth===0,d));
    if ((t.isClassDeclaration(n) || t.isClassExpression(n)) && n.id) declare(scope,n.id.name);
    if (t.isCatchClause(n) && n.param) names(n.param,name=>declare(scope,name));
    if (t.isImportDeclaration(n)) n.specifiers.forEach(p=>declare(scope,p.local.name));
    if (t.isWithStatement(n) || (t.isCallExpression(n) && t.isIdentifier(n.callee,{name:'eval'}) && !readOnlyLiteralEval(n))) scope.unsafe=true;
    const nextDepth = depth + (t.isBlockStatement(n) && n!==body ? 1 : 0);
    for (const key of t.VISITOR_KEYS[n.type] || []) {
      const value=n[key];
      if (Array.isArray(value)) value.forEach(c=>scan(c,scope,body,nextDepth));
      else if (value) scan(value,scope,body,nextDepth);
    }
  }
  scan(ast.program,root,ast.program);
  const resolve=(scope,name)=>{ for(let s=scope;s;s=s.parent) if(s.bindings.has(name)) return s.bindings.get(name); return null; };
  function visit(n,scope,callback) {
    if (!n) return;
    scope=scopes.get(n)||scope;
    callback(n,scope);
    for (const key of t.VISITOR_KEYS[n.type] || []) {
      const value=n[key];
      if (Array.isArray(value)) value.forEach(c=>visit(c,scope,callback));
      else if(value) visit(value,scope,callback);
    }
  }
  return {root,resolve,visit,scopes,names};
}
function stableBootstrap(ast, bootstrap, analysis) {
  let valid=true;
  const within=(n,container)=>n.start>=container.start && n.end<=container.end;
  analysis.visit(ast.program,analysis.root,(n,scope)=>{
    if (t.isIdentifier(n,{name:bootstrap.table.id.name}) &&
        ![bootstrap.table,bootstrap.decoder,bootstrap.rotate].some(c=>within(n,c))) valid=false;
    if (scope.unsafe) valid=false;
    if (t.isAssignmentExpression(n) || t.isUpdateExpression(n) || t.isForInStatement(n) || t.isForOfStatement(n)) {
      const left=t.isUpdateExpression(n)?n.argument:n.left;
      analysis.names(left,name=>{
        const binding=analysis.resolve(scope,name);
        if(binding) binding.mutable=true;
        if(name===bootstrap.decoder.id.name && !within(n,bootstrap.decoder)) valid=false;
      });
    }
  });
  for(const node of [bootstrap.table,bootstrap.decoder]) walk(node,n=>{
    if ((t.isAssignmentExpression(n) && t.isMemberExpression(n.left)) ||
        (t.isUpdateExpression(n) && t.isMemberExpression(n.argument)) ||
        (t.isCallExpression(n) && t.isMemberExpression(n.callee))) valid=false;
  });
  return valid;
}

function bootstrapContext(code) {
  const context = vm.createContext(Object.create(null), {codeGeneration:{strings:false,wasm:false}});
  vm.runInContext(code, context, {timeout:10000});
  return context;
}

function primitive(node) {
  if (t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node)) return {ok:true,value:node.value};
  if (t.isNullLiteral(node)) return {ok:true,value:null};
  if (t.isUnaryExpression(node) && ['-','+'].includes(node.operator) && t.isNumericLiteral(node.argument))
    return {ok:true,value:node.operator === '-' ? -node.argument.value : +node.argument.value};
  return {ok:false};
}

function recover() {
  const source = fs.readFileSync(input, 'utf8');
  const ast = parser.parse(source, {sourceType:'unambiguous', errorRecovery:false});
  let bootstrap = detectBootstrap(ast.program);
  const analysis = analyzeScopes(ast);
  if (bootstrap && !stableBootstrap(ast, bootstrap, analysis)) bootstrap = null;
  let folded = 0, checked = 0;
  const decodedHash = crypto.createHash('sha256');
  let decoderFunction, regeneratedDecoder, decoderBinding;
  if (bootstrap) {
    // The synthetic ExpressionStatement has no location. Use its actual call.
    const originalBootstrap = source.slice(bootstrap.table.start,bootstrap.table.end) + '\n' +
      source.slice(bootstrap.decoder.start,bootstrap.decoder.end) + '\n(' + source.slice(bootstrap.rotate.start,bootstrap.rotate.end) + ');';
    const rebuiltBootstrap = generate(t.file(t.program(bootstrap.nodes)), {comments:false}).code;
    const originalContext = bootstrapContext(originalBootstrap);
    const rebuiltContext = bootstrapContext(rebuiltBootstrap);
    decoderFunction = vm.runInContext(bootstrap.decoder.id.name, originalContext);
    regeneratedDecoder = vm.runInContext(bootstrap.decoder.id.name, rebuiltContext);
  }
  const cache = new Map();
  const bootstrapNodes = bootstrap ? new Set([bootstrap.table,bootstrap.decoder,bootstrap.rotate]) : new Set();
  decoderBinding = bootstrap ? analysis.root.bindings.get(bootstrap.decoder.id.name) : null;
  function decoderAlias(binding,visited=new Set()) {
    if (!binding || visited.has(binding)) return false;
    if (binding===decoderBinding) return true;
    visited.add(binding);
    return binding.eligible && !binding.mutable && t.isIdentifier(binding.init) &&
      decoderAlias(analysis.resolve(binding.scope,binding.init.name),visited);
  }
  function transform(n,scope) {
    if (!n || bootstrapNodes.has(n)) return n;
    scope = analysisScope(n,scope);
    let safe=true;
    for(let s=scope;s;s=s.parent) if(s.unsafe) safe=false;
    if (safe && bootstrap && n.start >= bootstrap.rotate.end && t.isCallExpression(n) && t.isIdentifier(n.callee) &&
        decoderAlias(analysis.resolve(scope,n.callee.name))) {
      const args=n.arguments.map(primitive);
      if(args.length && args.every(a=>a.ok)) {
        const values=args.map(a=>a.value),key=JSON.stringify(values);
        let value=cache.get(key);
        if(!cache.has(key)) {
          value=decoderFunction(...values);
          const other=regeneratedDecoder(...values);
          if(typeof value!=='string' || value!==other) throw new Error('DECODER_REGENERATION_MISMATCH');
          cache.set(key,value); checked++;
          decodedHash.update(key);decodedHash.update('\0');decodedHash.update(value);decodedHash.update('\0');
        }
        // Parentheses prevent a decoded string expression becoming a new
        // directive such as 'use strict' at the start of a function body.
        folded++; return t.parenthesizedExpression(t.stringLiteral(value));
      }
    }
    for(const key of t.VISITOR_KEYS[n.type] || []) {
      if(Array.isArray(n[key])) n[key]=n[key].map(c=>transform(c,scope));
      else if(n[key]) n[key]=transform(n[key],scope);
    }
    return n;
  }
  function analysisScope(n,scope) { return analysis.scopes.get(n)||scope; }
  transform(ast.program,analysis.root);
  // Source is regenerated from the AST; no application-specific code is added.
  const recovered = generate(ast, {comments:true, compact:false, minified:false, jsescOption:{minimal:true}}).code + '\n';
  fs.mkdirSync(path.dirname(output), {recursive:true});
  fs.writeFileSync(output, recovered);
  const report = {status:'GENERATED_UNVERIFIED', original_sha256:hash(source), generated_sha256:hash(recovered),
    source_bytes:Buffer.byteLength(source), generated_bytes:Buffer.byteLength(recovered),
    parsed:true, pure_bootstrap_recognized:!!bootstrap, folded_decoder_calls:folded,
    distinct_decoder_arguments_checked:checked, decoder_reconstruction_checks_sha256:decodedHash.digest('hex'),
    application_entry_executed:false, pure_decoder_bootstrap_evaluated:!!bootstrap, ui_verified:false, api_verified:false,
    toolchain:{parser:dependency('@babel/parser/package.json').version,generator:dependency('@babel/generator/package.json').version,
      scope_analysis:'conservative function scopes; block declarations mask enclosing function'}};
  fs.writeFileSync(reportFile, JSON.stringify(report,null,2));
  console.log(JSON.stringify(report));
}
try { recover(); }
catch (e) {
  fs.writeFileSync(reportFile, JSON.stringify({status:'INCOMPLETE', reason:e.message},null,2));
  console.error(e.stack); process.exitCode=1;
}
