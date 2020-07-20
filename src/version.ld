BDVMI_1.0 {
	extern "C++" {
		bdvmi::*;
		"typeinfo for std::runtime_error";
		"typeinfo for std::exception";
	};
};

# this is where private symbols go
BDVMI_priv {
	local:
		*;
};
