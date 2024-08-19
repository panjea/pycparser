I32 foo(U8 *x="A", I32 y, I32 z){
    return y+z;
}
I32 bar(U8 *x="B", U8 *y="C", I32 z){
    foo(,z,z);
}
U0 test(){
    bar(,,1);
    bar(,1,2);
}