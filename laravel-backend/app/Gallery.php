<?php

namespace App;

use Illuminate\Database\Eloquent\Model;
use Nicolaslopezj\Searchable\SearchableTrait;

class Gallery extends Model
{
    use SearchableTrait;
    protected $searchable = [
        'columns' => [
            'galleries.Gallery' => 30,
            'tasks.name' => 50,
        ],
        'joins' => [
            'tasks' => ['tasks.id','comments.task_id'],
        ],
    ];
    public function Tasks()
    {
        return $this->belongsTo('App\Task');
    }
    protected $fillable= ['filename','size','task_id'];
}
