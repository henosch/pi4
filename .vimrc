set encoding=utf-8

" Disable compatibility with vi which can cause unexpected issues.
set nocompatible

" Arrow key fix
set backspace=2

" Do not save backup files.
set nobackup

" Set tab width to 4 columns.
set tabstop=4

" Do not wrap lines. Allow long lines to extend as far as the line goes.
set nowrap

" While searching though a file incrementally highlight matching characters as you type.
set incsearch

" Use highlighting when doing a search.
set hlsearch

" Show partial command you type in the last line of the screen.
set showcmd

" Show the mode you are on the last line.
set showmode

" Show matching words during a search.
set showmatch

" Do not let cursor scroll below or above N number of lines when scrolling.
set scrolloff=10

colorscheme desert

" Turn syntax highlighting on.
syntax on


" To save all the buffer-local maps for the current buffer
" :redir! > vim_maps.txt
" :map
" :map!
" :redir END


" Bash like keys for the command line

cnoremap <C-A> <Home>
cnoremap <C-E> <End> 
cnoremap <C-K> <C-U>
cnoremap <C-P> <Up>
cnoremap <C-N> <Down>

" inoremap – Allows you to map keys in insert mode.
" nnoremap – Allows you to map keys in normal mode.
" vnoremap – Allows you to map keys in visual mode.

" Pressing the letter o will open a new line below the current one.
" Exit insert mode after creating a new line above or below the current line.
nnoremap o o<esc>


" Return to last edit position when opening files (You want this!)
au BufReadPost * if line("'\"") > 1 && line("'\"") <= line("$") | exe "normal! g'\"" | endif

" Enable auto completion menu after pressing TAB.
set wildmenu

" Make wildmenu behave like similar to Bash completion.
set wildmode=list:longest

" There are certain files that we would never want to edit with Vim.
" Wildmenu will ignore files with these extensions.
set wildignore=*.docx,*.jpg,*.png,*.gif,*.pdf,*.pyc,*.exe,*.flv,*.img,*.xlsx



" STATUS LINE --------------------------------------------------------


set laststatus=2
set statusline=
set statusline +=%1*\ %n\ %*            			 "buffer number
set statusline +=%5*%{strlen(&fenc)?&fenc:'none'}%*  "file encoding 
" set statusline +=%3*%y%*                			 "file type
set statusline +=%4*\ %<%F%*            			 "full path
set statusline +=%2*%m%*                			 "modified flag
set statusline +=%1*%=%5l%*             			 "current line
set statusline +=%1*/%L%*               		     "total lines
set statusline +=%1*%4v\ %*             			 "virtual column number
set statusline +=%3*0x%04B\ %*    			 		 "character under cursor
set statusline +=%7*%p%%\ %*                 		 "percent from file

hi User2 ctermbg=lightgreen ctermfg=black guibg=lightgreen guifg=black
hi User1 ctermbg=black ctermfg=white guibg=black guifg=white
hi User3 ctermbg=black ctermfg=lightblue guibg=black guifg=lightblue
hi User4 ctermbg=black ctermfg=lightgreen guibg=black guifg=lightgreen
hi User5 ctermbg=black ctermfg=magenta guibg=black guifg=magenta
hi User6 ctermbg=red ctermfg=white guibg=red guifg=white
hi User7 ctermbg=green ctermfg=white guibg=green guifg=white

set statusline+=%6*
set statusline+=%{StatuslineMode()}

function! StatuslineMode()
  let l:mode=mode()
  if l:mode==#"n"
    return "NORMAL"
  elseif l:mode==?"v"
    return "VISUAL"
  elseif l:mode==#"i"
    return "INSERT"
  elseif l:mode==#"R"
    return "REPLACE"
  elseif l:mode==?"s"
    return "SELECT"
  elseif l:mode==#"t"
    return "TERMINAL"
  elseif l:mode==#"c"
    return "COMMAND"
  elseif l:mode==#"!"
    return "SHELL"
  endif
endfunction

