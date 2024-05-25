<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    // Register user
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:8',
            ]);

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => bcrypt($request->password),
            ]);

            return response()->json(['message' => 'User successfully registered', 'data' => $user], 201);
        } catch (\Throwable $th) {
            return response()->json(['message' => 'throwable error', $th->getMessage()], 422);
        } catch (ValidationException $e) {
            return response()->json(['message' => 'validation error', $e->errors()], 422);
        } catch (\Exception $e) {
            return response()->json(['message' => 'unexpected error', $e->getMessage()], 422);
        }
    }

    public function test()
    {
        return response()->json(['message' => 'tes'], 200);
    }
    // Login user
    public function login(Request $request)
    {
        try {
            $credentials = $request->only('email', 'password');

            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }

            return response()->json(['token' => $token]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        } catch (JWTException $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        } catch (\Throwable $th) {
            return response()->json(['message' => 'throwable error', $th->getMessage()], 422);
        }
    }


    // Refresh token
    public function refresh()
    {
        return $this->respondWithToken(Auth::refresh());
    }

    // Logout user
    public function logout()
    {
        Auth::logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    // Get the authenticated user
    public function me()
    {
        return response()->json(Auth::user());
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60,
        ]);
    }
}
