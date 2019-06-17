src_code_dir=compiler
cd "${src_code_dir}"
for f in $(ls *.py ); do
	
	echo filename is $f
	if [[ "$f" == "__init__.py" ]]; then
		continue
	fi
	pydoc3 -w "${f%.*}" #remove file type suffix
done 
doc_dir="../documentation"
if [[ ! -d "${doc_dir}" ]]; then
	mkdir "${doc_dir}"	
fi

mv *html "${doc_dir}"

src_code_dir2=primitives
cd $src_code_dir2

for f in $(ls *.py ); do
	
	echo filename is $f
	if [[ "$f" == "__init__.py" ]]; then
		continue
	fi
	pydoc3 -w "${f%.*}" #remove file type suffix
done 
doc_dir="../../documentation/primitives"
if [[ ! -d "${doc_dir}" ]]; then
	mkdir "${doc_dir}"	
fi
mv *html "${doc_dir}"
cd ../..