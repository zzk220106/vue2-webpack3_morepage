/**
 * Created by kenny on 17/4/21.
 */
"use strict";
(function (global, nav, undefined) {
  var getCurrentScript = function () {
    if (document.currentScript) {
      return document.currentScript.src;
    } else {
      var scripts = document.getElementsByTagName('script');
      return scripts[scripts.length - 1].src;
    }
  };
  var src = getCurrentScript();
  var currentScriptBase = src.substring(0, src.lastIndexOf("/")) + "/";
  var ua = nav.userAgent;
  //默认运行纯web环境
  var runtime = '.web',
    sdkenv = '.wuat2',
    sdk = '-stg',
    sdc;
  //运行时是阿拉丁壳
  if (ua.indexOf("AladdinHybrid") > 0) {
    runtime = "";
  } else {
    sdc = currentScriptBase.substring(0, src.lastIndexOf("/aladdin")) + '/tools/sdc9_m.js'
  }
  if (/stg.pingan.com.cn/.test(location.href)) {
    sdk = '-stg';
    sdkenv = '.wuat2';
  } else {
    sdkenv = '.min';
    sdk = '';
  }
  //与运行时环境有关系的库文件
  var deps = [
    "aladdin.ibank{environment}.min.js",
  ];
  var depscripts = '';
  for (var i = 0, len = deps.length; i < len; i++) {
    depscripts += '<script src="' + currentScriptBase + deps[i] + '"></script>\n';
  }
  if (sdc) {
    depscripts += '<script src="' + sdc + '"></script>\n';
  }
  if (ua.indexOf("AladdinHybrid") == -1) {
    depscripts += '<script src="https://bank-static' + sdk + '.pingan.com.cn/ibank/member/sdk/auth-sdk' + sdkenv + '.js"></script>\n';
  }
  document.write(depscripts.replace(/\{environment\}/g, runtime));

}(window, navigator));
