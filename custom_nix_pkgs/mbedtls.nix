{ lib
, stdenv
, cmake
, perl
, python39
, python311Packages
, ninja
}:

stdenv.mkDerivation rec {
  pname = "mbedtls";
  version = "3.5.2";

  src = builtins.fetchGit {
    url = "https://github.com/Mbed-TLS/mbedtls.git";
    ref = "refs/tags/v3.5.2";
  };

  buildInputs = [
    python39
    perl
    cmake
    ninja
    python311Packages.markupsafe
    python311Packages.jinja2
    python311Packages.jsonschema
  ]; # Add dependencies if there are any.


  # The build phase is usually 'make', but you can specify it explicitly if needed
  buildPhase = "make";

  # The install phase is usually 'make install', but you can specify it explicitly if needed
  installPhase = "make install";

  meta = with lib; {
    description = "An open source, portable, easy to use, readable and flexible SSL library";
    homepage = "https://tls.mbed.org";
    license = licenses.gpl2Plus; # Specify the correct license here
    maintainers = with maintainers; [ Zheyuan Ma ]; # Add maintainers if available
  };
}