<?php

namespace App;

use Illuminate\Database\Eloquent\Model;
use Nicolaslopezj\Searchable\SearchableTrait;

class Category extends Model
{
    use SearchableTrait;
    protected $searchable = [
        'columns' => [
            'customers.name' => 12,
            'customers.description' => 7,
        ],
    ];
    public function Task()
    {
        return $this->hasMany('App\Task');
    }

    protected $fillable = [
        'name','description'
    ];
}
