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

            return jsonResponse(null, 201, 'User successfully registered');
        } catch (\Throwable $e) {
            return jsonResponse(null, 422, $e->getMessage());
        } catch (ValidationException $e) {
            return jsonResponse(null, 422, $e->getMessage());
        } catch (\Exception $e) {
            return jsonResponse(null, 422, $e->getMessage());
        }
    }


    // Fungsi login yang telah diubah
    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required|string|email|max:255',
                'password' => 'required|string',
            ]);

            $credentials = $request->only('email', 'password');

            if (!Auth::attempt($credentials)) {
                return jsonResponse(null, 401, 'Invalid email or password');
            }


            $token = $this->createAccessToken($credentials);
            $refreshToken = $this->createRefreshToken();

            if (!$token || !$refreshToken) {
                return jsonResponse(null, 401, 'Unauthorized');
            }

            $data = [
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => JWTAuth::factory()->getTTL() * 60,
                'refresh_token' => $refreshToken,
            ];

            return jsonResponse($data, 200, 'Login successful')
                ->header('Authorization', 'Bearer ' . $token);
        } catch (\Exception $e) {
            return jsonResponse(null, 422, $e->getMessage());
        } catch (ValidationException $e) {
            return jsonResponse(null, 422, $e->getMessage());
        } catch (\Throwable $th) {
            return jsonResponse(null, 422, $th->getMessage());
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
        } catch (\Throwable $th) {
            return jsonResponse(null, 422, "Failed to refresh token");
        }
    }

    // Get the authenticated user
    public function me()
    {
        return jsonResponse(Auth::user(), 200);
    }

    public function logout(Request $request)
    {
        try {
            // Invalidate both access token and refresh token
            $accessToken = JWTAuth::getToken();
            $refreshToken = $request->input('refresh_token');

            JWTAuth::invalidate($accessToken);

            Auth::logout();
            return jsonResponse(null, 200, 'Successfully logged out');
        } catch (\Throwable $th) {
            return jsonResponse(null, 422, "Failed logged out");
        }
    }
}
