import axios, { AxiosError, AxiosResponse } from "axios";
import { GetServerSidePropsContext } from "next";
import { parseCookies, setCookie } from "nookies";
import { signOut } from "../contexts/AuthContext";
import { AuthTokenError } from "./errors/AuthTokenError";

type FailedRequestQueue = {
    onSuccess: (token: string) => void;
    onFailure: (err: AxiosError) => void;
};

type Context = undefined | GetServerSidePropsContext;

let isRefreshing = false;
let failedRequestsQueue = Array<FailedRequestQueue>();;

export function setupAPIClient(ctx: Context = undefined) {
    let cookies = parseCookies(ctx);

    const api = axios.create({
        baseURL: 'http://localhost:3333',
    });
    
    api.defaults.headers.common["Authorization"] = `Bearer ${cookies["nextauth.token"]}`;
    
    api.interceptors.response.use(response => {
        return response;
    }, (error: AxiosError) => {
        if (error.response?.status === 401) {
            const reponseError = error.response as AxiosResponse;
    
            if (reponseError?.data?.code === 'token.expired') {
                // renovar token
                cookies = parseCookies(ctx);
    
                const { 'nextauth.refreshToken': refreshToken } = cookies;
                const originalConfig = error.config;
    
                if (!isRefreshing) {
                    isRefreshing = true;
    
                    api.post('/refresh', {
                        refreshToken,
                    }).then(response => {
                        const { token } = response.data;
    
                        setCookie(ctx, 'nextauth.token', token, {
                            maxAge: 60 * 60 * 24 * 30, // 30 days
                            path: '/'
                        });
    
                        setCookie(ctx, 'nextauth.refreshToken', response.data.refreshToken, {
                            maxAge: 60 * 60 * 24 * 30, // 30 days
                            path: '/'
                        });
    
                        api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
    
                        failedRequestsQueue.forEach(req => { req.onSuccess(token)});
                        failedRequestsQueue = [];
                    }).catch(err => {
                        failedRequestsQueue.forEach(req => { req.onFailure(err)});
                        failedRequestsQueue = [];
    
                        if (process.browser) {
                            signOut();
                        }
                    }).finally(() => {
                        isRefreshing = false;
                    });
                }
    
                return new Promise((resolve, reject) => {
                    failedRequestsQueue.push({
                        onSuccess: (token: string) => {
                            if ( originalConfig.headers ) {
                                originalConfig.headers['Authorization'] = `Bearer ${token}`;
    
                                resolve(api(originalConfig));
                            }
                        },
                        onFailure: (err: AxiosError) => {
                            reject(err);
                        }
                    });
                });
            } else {
                // deslogar usuário
                if (process.browser) {
                    signOut();
                } else {
                    return Promise.reject(new AuthTokenError());
                }
            }
        }
    
        return Promise.reject(error);
    });

    return api;
}