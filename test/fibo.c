
int fibo(int n){
    if(n < 2) return 1;
    return fibo(n - 1) + fibo(n - 2);
}

int f(){
    int i = 5;
    return fibo(i);
}