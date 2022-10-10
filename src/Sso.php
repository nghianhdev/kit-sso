<?php

namespace Uniconnect\KitSso;

use Carbon\Carbon;

/**
 *  シングルサインオンを実現するためのメソッドを提供するクラスです。
 */
class Sso
{
    public static $default_valid_time = 3600;

    /**
     * @param redirect_to [String] 認証後の遷移に用いる値、あればこれもトークン生成に用いる
     *                             ただし遷移自体はアプリ側で実装すること（認証packageの責務ではない）
     * @return [Hash] 認証リクエストに付加するクエリパラメータで構成されたハッシュ
     */
    public static function createSSOToken(
        int $userType,
        string $userCode,
        int $collegeCode,
        string $createdTime,
        string $redirectTo = "",
        string $secretToken
    ) {
        $array = [
            $userType,
            $userCode,
            $collegeCode,
            $createdTime,
            $redirectTo,
            $secretToken
        ];

        $array = array_filter($array, 'strlen');
        // return openssl_digest(join("", $array), "sha256");
        return hash("sha256", join("", $array));
    }

    /**
     * @return [true,false] 認証トークンが正当であるか否かを表す真偽値
     */
    public static function compareSSOToken($request, $secretToken)
    {
        $token = self::createSSOToken(
            $request->input('t'),
            $request->input('u'),
            $request->input('c'),
            $request->input('p'),
            $request->input('r') ?? "",
            $secretToken
        );
        return $request->input('a') === $token;
    }

    /**
     * @return [true,false] 認証トークンが有効期限内にあるか否かを表す真偽値
     */
    public static function isExpired($publishTime)
    {
        $startTime = Carbon::createFromFormat('YmdHis', $publishTime)->subSeconds(self::$default_valid_time);
        $limitTime = Carbon::createFromFormat('YmdHis', $publishTime)->addSeconds(self::$default_valid_time);

        return Carbon::now()->between($startTime, $limitTime);
    }
}
