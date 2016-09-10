<?php

namespace App\Http\Controllers;

use App\role_user;
use Illuminate\Http\Request;
use App\Role;
use App\User;
use App\Http\Requests;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthenticateController extends Controller
{

    public function authenticate(Request $request)
    {
	    $permissions=array();
        $credentials = $request->only('email', 'password');

        try {
            // verify the credentials and create a token for the user
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Invalid Credentials'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong
            return response()->json(['error' => 'could_not_create_token'], 500);
        }
        $role = DB::table('role_user')->where('user_id',Auth::user()->id)->first();
        $role = Role::find($role->role_id);
        $user=Auth::user();
        $temp=$role->perms()->get()->lists('name');
        foreach($temp as $value){
            $permissions[]=$value;
         }
        $user->permissions=$permissions;
        return response()->json(compact('token','user'));
 
    }

}
