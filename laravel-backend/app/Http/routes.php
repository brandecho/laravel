<?php


Route::group(['prefix' => 'api'], function()
{

    /*
   * import excel csv Route
   */
    Route::post('user/import_excel_csv','ImportController@importCSVEXCEl');
    Route::post('user/import_excel_csv_database','ImportController@importCSVEXCElDatabase');
    Route::post('user/{id}/delete_excel_csv','ImportController@deleteCSVEXCEl');



    // Password reset link request routes...
    Route::post('password/email', 'Auth\PasswordController@postEmail');

    // Password reset routes...
    Route::post('password/reset', 'Auth\PasswordController@postReset');

    // authentication
    Route::resource('authenticate', 'AuthenticateController', ['only' => ['index']]);
    Route::post('authenticate', 'AuthenticateController@authenticate');


    /*
     * User Route
     */
    Route::get('user/search','UserController@search');
    Route::resource('user', 'UserController');
    Route::get('user/export/file','UserController@exportFile');


    /*
     * Permission Route
     */
    Route::get('permission/search','PermissionController@search');
    Route::resource('permission', 'PermissionController');

    /*
     * Role Route
     */
    Route::get('role/search','RoleController@search');
    Route::resource('role', 'RoleController');

    /*
     * Task Route
     */
    Route::get('task/search','TaskController@search');
    Route::resource('task', 'TaskController');
    Route::get('task/export/file','TaskController@exportFile');
    /*
     * Comment Route
     */
    Route::get('comment/search','CommentController@search');
    Route::resource('comment', 'CommentController');

    /*
     * tag Route
     */
    Route::get('tag/search','TagController@search');
    Route::resource('tag', 'TagController');

    /*
     * Gallery Route
     */
    Route::get('gallery/search','GalleryController@search');
    Route::resource('gallery', 'GalleryController');


    /*
     * Category Route
     */
    Route::resource('category', 'CategoryController');

    /*
     * Upload image Controller
     */
    Route::post('/uploadimage','UploadController@uploadimage');
    Route::post('/deleteimage/{id}','UploadController@deleteUpload');
});


