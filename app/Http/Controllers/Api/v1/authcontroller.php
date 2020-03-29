<?php
//use Laravel\Passport\HasApiTokens;
namespace App\Http\Controllers\Api\v1;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Notifications\LogedInNotification;
use App\Notifications\RegistrationNotification;
use App\User;
use Illuminate\Http\Request;

class authcontroller extends Controller
{
    public function signUp(Request $request){
        $user= new User();
        $validated= $request->validate([
            'name'=>'required|string',
            'email' => 'email|required',
            'password'=> 'required|confirmed',

        ]);

        if(!$validated){
            return response(['message'=>'In']);
        }
        $password= bcrypt($request->password);
        $user->name=$request->name;
        $user->email = $request->email;
        $user->password = $password;
        $user->save();
        $user->notify(new RegistrationNotification);
        $token = $user->createToken('authToken')->accessToken;
        return response(['user' => $user, 'access_token' => $token]);
    }
    public function logIn(Request $request)
    {

        $validated = $request->validate([
            'email' => 'email|required',
            'password' => 'required',

        ]);

        if (!Auth::attempt($validated)) {
            return response(['message' => 'Invalid login credentials']);
        }
        $user = Auth::user();
        $user->notify(new LogedInNotification);
        $token = $user->createToken('authToken')->accessToken;
        return response(['user'=> $user,'access_token'=>$token] );


    }
}
