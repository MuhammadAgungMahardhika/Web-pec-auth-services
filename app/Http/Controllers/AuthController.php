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
                'id_role' => 'required|integer',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:8',
            ]);

            $user = User::create([
                'name' => $request->name,
                'id_role' => $request->id_role,
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


    // Login user
    public function login(Request $request)
    {
        try {
            $credentials = $request->only('email', 'password');
            $token = $this->createAccessToken($credentials);
            $refreshToken = $this->createRefreshToken();
            if (!$token || !$refreshToken) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }

            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' =>  JWTAuth::factory()->getTTL() * 60,
                'refresh_token' => $refreshToken
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        } catch (JWTException $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        } catch (\Throwable $th) {
            return response()->json(['message' => 'throwable error', $th->getMessage()], 422);
        }
    }


    // Access token
    protected function createAccessToken($credentials)
    {
        return JWTAuth::attempt($credentials);
    }
    // Refresh token
    protected function createRefreshToken()
    {
        return JWTAuth::claims(['exp' => now()->addMinutes(config('jwt.refresh_ttl'))->timestamp])->fromUser(Auth::user());
    }
    // New Access token
    protected function createNewAccessToken($lastToken)
    {
        return JWTAuth::refresh($lastToken);
    }
    // New Refresh token
    protected function createNewRefreshToken($user)
    {
        return JWTAuth::claims(['exp' => now()->addMinutes(config('jwt.refresh_ttl'))->timestamp])->fromUser($user);
    }

    public function refresh()
    {
        try {

            $user = JWTAuth::parseToken()->authenticate();
            $lastToken = JWTAuth::getToken();
            $newToken = $this->createNewAccessToken($lastToken);
            $newRefreshToken = $this->createNewRefreshToken($user);
            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'bearer',
                'expires_in' => JWTAuth::factory()->getTTL() * 60,
                'refresh_token' => $newRefreshToken
            ]);
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_refresh_token'], 422);
        }
    }

    // Get the authenticated user
    public function me()
    {
        return response()->json(Auth::user());
    }

    public function logout(Request $request)
    {
        try {
            // Invalidate both access token and refresh token
            $accessToken = JWTAuth::getToken();
            $refreshToken = $request->input('refresh_token');

            JWTAuth::invalidate($accessToken);

            Auth::logout();
            return response()->json(['message' => 'Successfully logged out' + $refreshToken]);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to logout, please try again.'], 500);
        }
    }
}
