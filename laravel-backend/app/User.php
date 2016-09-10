<?php

namespace App;

use Illuminate\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Auth\Passwords\CanResetPassword;
use Illuminate\Foundation\Auth\Access\Authorizable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;
use Nicolaslopezj\Searchable\SearchableTrait;
use PhpSoft\Users\Models\UserTrait;

class User extends Model implements AuthenticatableContract,
                                    //AuthorizableContract,
                                    CanResetPasswordContract
{
    use SearchableTrait;
    protected $searchable = [
        'columns' => [
            'users.name' => 1,
            'users.email' => 200,
            'users.location' => 3,
            'users.country' => 4,
            'users.website' => 5,
            'users.gender' => 6
        ],
    ];
    use Authenticatable, CanResetPassword,UserTrait;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'users';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'username',
        'location',
        'country',
        'biography',
        'occupation',
        'website',
        'image',
        'birthday',
        'gender',
        'avatar_url',
        'status'
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = ['password', 'remember_token'];

    public function Task()
    {
        return $this->hasMany('App\Task');
    }
    public function Comment()
    {
        return $this->hasMany('App\Comment');
    }
   #### import fields
    public  $import_fields=['email','password','role','name','gender','status'];
}
