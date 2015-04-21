'use strict';

/**
 * @ngdoc function
 * @name webApp.controller:WorkCtrl
 * @description
 * # WorkCtrl
 * Controller of the webApp
 */
angular.module('webApp')
  .controller('WorkCtrl', function ($scope) {
    $scope.awesomeThings = [
      'HTML5 Boilerplate',
      'AngularJS',
      'Karma'
    ];
    $scope.$on('$viewContentLoaded', function(){
      var myCodeMirror = CodeMirror.fromTextArea(document.getElementById("asm"), {
        lineNumbers: true,
        mode: "gas",
        architecture: "x86"
      });
      console.log(myCodeMirror);
    });
  });
