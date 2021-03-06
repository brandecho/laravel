"use strict";

var url = 'server/php/';

var app = angular.module('ng-laravel',['blueimp.fileupload']);
app.controller('multipleFileUploadCtrl', ['$scope', '$http', '$filter', '$window', function ($scope, $http) {
        $scope.options = {
            url: url
        };

        $scope.loadingFiles = true;
        $http.get(url)
            .then(
            function (response) {
                $scope.loadingFiles = false;
                $scope.queue = response.data.files || [];
            },
            function () {
                $scope.loadingFiles = false;
            }
        );

    }
]).controller('FileDestroyController', ['$scope', '$http', function ($scope, $http) {
        var file = $scope.file,
            state;
        if (file.url) {
            file.$state = function () {
                return state;
            };
            file.$destroy = function () {
                state = 'pending';
                return $http({
                    url: file.deleteUrl,
                    method: file.deleteType
                }).then(
                    function () {
                        state = 'resolved';
                        $scope.clear(file);
                    },
                    function () {
                        state = 'rejected';
                    }
                );
            };
        } else if (!file.$cancel && !file._index) {
            file.$cancel = function () {
                $scope.clear(file);
            };
        }
    }
]);
