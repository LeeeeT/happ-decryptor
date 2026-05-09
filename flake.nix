{
  description = "Development shell for the Happ Link Decryptor web app";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.nodejs_20 ];

            shellHook = ''
              echo "Node: $(node --version)"
              echo "npm:  $(npm --version)"
              echo
              echo "Install dependencies with: npm install"
              echo "Start the dev server with: npm run dev -- --host"
            '';
          };
        });
    };
}
