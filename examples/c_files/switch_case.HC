I32 switch_case_test(I32 i){
	switch (i){
		case: return 0;
		case: return 1;
		case 2: return 2;
		case 3 ... 10: return 3;
	}
	return -1;
}

