#!/usr/bin/env node
// Research type-aware authoring lint. This is a guardrail, not a JavaScript sandbox.
import ts from 'typescript';
import {pathToFileURL} from 'node:url';
export function lintSymbolic(files){
  const program=ts.createProgram(files,{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.NodeNext,
    moduleResolution:ts.ModuleResolutionKind.NodeNext,strict:true,noEmit:true,skipLibCheck:true});
  const checker=program.getTypeChecker(),diagnostics=[];
  function symbolicType(t){return !!t.getProperty('__zerojSymbolic')||(t.isUnionOrIntersection()&&t.types.some(symbolicType));}
  const symbolic=n=>n&&symbolicType(checker.getTypeAtLocation(n));
  for(const file of program.getSourceFiles())if(files.includes(file.fileName)){
    function visit(n){
      let bad=false;
      if(ts.isIfStatement(n)||ts.isWhileStatement(n)||ts.isDoStatement(n)||ts.isConditionalExpression(n))bad=symbolic(n.expression??n.condition);
      if(ts.isForStatement(n))bad=symbolic(n.condition);
      if(ts.isSwitchStatement(n))bad=symbolic(n.expression);
      if(ts.isBinaryExpression(n)&&n.operatorToken.kind!==ts.SyntaxKind.EqualsToken)bad=symbolic(n.left)||symbolic(n.right);
      if(ts.isPrefixUnaryExpression(n)||ts.isPostfixUnaryExpression(n))bad=symbolic(n.operand);
      if(ts.isTemplateExpression(n))bad=n.templateSpans.some(s=>symbolic(s.expression));
      if(ts.isCallExpression(n)&&ts.isIdentifier(n.expression)&&['Boolean','Number','String','BigInt'].includes(n.expression.text))bad=n.arguments.some(symbolic);
      if(bad){const p=file.getLineAndCharacterOfPosition(n.getStart());diagnostics.push(`${file.fileName}:${p.line+1}:${p.character+1}: SYMBOLIC_JS_VALUE: use symbolic methods and select(), not JS operators or conditions`);}
      ts.forEachChild(n,visit);
    }
    visit(file);
  }
  return diagnostics;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const diagnostics=lintSymbolic(process.argv.slice(2));for(const d of diagnostics)console.error(d);if(diagnostics.length)process.exitCode=1;
}
