#include <gcc-plugin.h>

#include <stdio.h>
#include <cpplib.h>
#include <gimple.h>
#include <string.h>
#include <cfgloop.h>
#include <stdbool.h>
#include <function.h>
#include <tree-pass.h>
#include <basic-block.h>
#include <c-family/c-common.h>
#include <c-family/c-pragma.h>

#define LOAD  0
#define STORE 1

#define INS_ENTRY 0
#define INS_EXIT  1

#define MAX_STR 1024
#define MAX_FCT 1024
#define MAX_BB  2048

//
int   plugin_is_GPL_compatible;

//
int   op_uid = 0;

//
FILE *g_out = NULL; //Graph output file !
FILE *m_out = NULL;

int  f_nb = 0;
char f_mask[MAX_FCT];
char f_list[MAX_FCT][MAX_STR];

int loop_id = 0;
int load    = 0, store  = 0;
int gload   = 0, gstore = 0;

//Plugin information
static struct plugin_info zebu_plugin_infos =
{
  .version = "0.1",
  .help    = 
  
  "-- Written by Yaspr (copyleft) 2013 -- "
  "This plugin is used to instrument and profile   "
  "statically & dynamically programs compiled with "
  "the GNU C Compiler."
};

//Looks up a function in the f_list !
int f_lookup(const char *f_name)
{
  int i, found = 0;
  
  for (i = 0; !found && i < f_nb; i++)
    found = !strcmp(f_list[i], f_name);
  
  return (found) ? i - 1 : -1;
}

//If the compiler does an estimation then return that estimation 
//If no estimation then unknown number of iterations !
int get_loop_iter(struct loop *loop)
{
  unsigned ubound = 0;
  
  if(loop->any_upper_bound)
    if (loop->any_estimate)
      ubound = loop->nb_iterations_upper_bound.to_uhwi() + 1; //Convert a double_int into an unsigned !
    else
      return -1;
  
  return ubound;
}

//
void op_span(tree op, int op_type)
{
  tree operand;
  
  //Check the 
  switch(TREE_CODE(op))
    {
      //If the access is of the form ARRAY_BASE[ARRAY_INDEX]([ARRAY_INDEX] | eps)
    case ARRAY_REF   :
      
      //ARRAY_BASE
      op_span(TREE_OPERAND(op, 0), LOAD); 
      
      //ARRAY_INDEX
      op_span(TREE_OPERAND(op, 1), LOAD);
      
      //Second part of the reference ... 
      op_span(TREE_OPERAND(op, 0), op_type);
      break;

      //Now you're talking !!
    case MEM_REF     :
    case ADDR_EXPR   :
      
      load  += (op_type == LOAD );
      store += (op_type == STORE); 
 
      break;
      
      //If not memory access then IGNORE !
    default :
      break;
    }

  //Get the operands at the 'i' position !
  for(int i = 0; i < TREE_OPERAND_LENGTH(op); i++)
    if ((operand = TREE_OPERAND(op, i)))  
      op_span(operand, op_type);
}

//
int count(basic_block bb, int it, int depth)
{
  int loc_l = 0, loc_s = 0;
  gimple               stmt;
  gimple_stmt_iterator g_stmt_iter;
  
  load = store = 0;
  
  for (g_stmt_iter = gsi_start_bb(bb); !gsi_end_p(g_stmt_iter); gsi_next(&g_stmt_iter))
    {
      stmt = gsi_stmt(g_stmt_iter);
      
      switch(gimple_code(stmt))
	{
	case GIMPLE_COND :
	  op_span(gimple_cond_lhs(stmt), LOAD); //Left hand side of the condition !
	  op_span(gimple_cond_rhs(stmt), LOAD); //Right hand side of the condition !
	  break;
	  
	case GIMPLE_ASSIGN : //y = a + b - 1;
	  op_span(gimple_op(stmt, 0), STORE); //y is stored ! 
	  op_span(gimple_op(stmt, 1), LOAD ); //a & b are read !
	  
	  //Span
	  if(gimple_num_ops(stmt) > 2)
	    op_span(gimple_op(stmt, 2), LOAD);
	  
	  break;
	  
	case GIMPLE_CALL :
	  //Check all the function parameters which are only read.
	  //If any must be changed, a store will occur in the body !
	  for (int i = 0; i < gimple_call_num_args(stmt); i++)
	    op_span(gimple_call_arg(stmt, i), LOAD);
	  
	  break;
	}
    }
  
  //Nothing to do if both null
  if (load || store) 
    {
      if (it > 0)
	loc_l = load,
	loc_s = store,
	load  *= it, 
	store *= it;

      for (int i = 0; i < 2 * depth; i++)
	fprintf(m_out, " ");
      
      fprintf(m_out, "--> loads : %d (%d x %d) stores : %d (%d x %d)\n", load, loc_l, it, store, loc_s, it);
      
      gload += load;
      gstore += store;
    }
  
  return 0;
}

//Handles loops which number of iterations isn't known ... 
int detect_loop_ubound(struct loop *loop, basic_block *bb_to_avoid, int *nb_bb, int depth, int iter)
{
  //Get the number of iterations 
  int it = get_loop_iter(loop);
  
  //beauty : showing nested loops !
  for (int i = 0; i < depth; i++)
    printf(" ");
  
  if (it > 0) //If estimated by the compiler
    {
      iter *= it;
      fprintf(m_out, "Loop [%d] with %d iterations\n", loop_id++, it);
    }
  else
    if (it < 0) //If couldn't be estimated then unknown (usually it's a parameter)
      fprintf(m_out, "Loop [%d] with unknow number of iterations\n", loop_id++);
  
  //
  bb_to_avoid[(*nb_bb)++] = loop->header;
  count(loop->header, iter, depth);
  
  //Check inner loops ...
  for (struct loop *l = loop->inner; l != NULL; l = l->next)
    detect_loop_ubound(l, bb_to_avoid, nb_bb, depth + 1, iter);
}

//
unsigned int load_store_exec()
{
  int f_pos;
  const char * f_name = gimple_decl_printable_name(cfun->decl, 1);
  
  if ((f_pos = f_lookup(f_name)) != -1)
    { 
      f_mask[f_pos] = 1;

      loop_id = 0;
      
      fprintf(m_out, "\nStatic pass stats on %s : \n", f_name);	
      
      int nb_bb = 0, found;
      basic_block bb_to_avoid[MAX_BB], bb;
      
      //Detects & counts the loops !
      detect_loop_ubound(current_loops->tree_root, bb_to_avoid, &nb_bb, -1, 1);
      
      //Counts and avoids the loops !
      FOR_ALL_BB(bb)
      {
	//If basic block found then avoid it 'cause it's a loop basic block ! 
	found = 0;
	for (int i = 0; !found && i < nb_bb; i++)
	  found = (bb == bb_to_avoid[i]);
	
	if (!found)
	  count(bb, 1, 0);
      }
    }
  
  return 0;
}

//
void span_tree_op(const_tree op, char *parent)
{
  const_tree  oprd;
  const char *data, *end;
  char        local_id[MAX_STR];
  
  if (op)
    { 
      sprintf(local_id , "FUNC%d_OP_%d", 
	      current_function_funcdef_no, op_uid++);
      
      fprintf(g_out, "%s [label=\"_OP_ %s::%s\" color=yellow]\n", 
	      local_id, 
	      tree_code_name[TREE_CODE(op)], 
	      TREE_CODE_CLASS_STRING(TREE_CODE_CLASS(TREE_CODE(op))));
      
      fprintf(g_out, " %s -> %s  [color=yellow]\n", 
	      parent, local_id );
      
      for(int i = 0 ; i < TREE_OPERAND_LENGTH(op); i++)
	oprd = TREE_OPERAND(op, i),
	  span_tree_op(oprd, local_id);
    }
}

//Dump the control flow graph into a dot file !
unsigned int cfg_exec()
{  
  basic_block          bb;
  gimple               g_stmt;
  int                  j      = 0;
  const_tree           op, operand;
  gimple_stmt_iterator g_stmt_iter;
  const char          *f_name = gimple_decl_printable_name(cfun->decl, 3); //Get function's prototype !
 
  FOR_ALL_BB(bb)
  {
    for (g_stmt_iter = gsi_start_bb(bb); !gsi_end_p(g_stmt_iter); gsi_next(&g_stmt_iter))
      g_stmt = gsi_stmt(g_stmt_iter),
      gimple_set_uid(g_stmt, j++);
  }
  
  //
  fprintf(g_out, "FUNC%d [label=\"%s\" shape=square]\n", 
	  current_function_funcdef_no, 
	  f_name);
  
  fprintf(g_out, "FUNC%d -> FUNC%d_BB_0\n", 
	  current_function_funcdef_no, 
	  current_function_funcdef_no);
  
  //Walk through GIMPLE cfg
  FOR_ALL_BB(bb)
  {
    char extra_BB[MAX_STR] = "\0";
    
    if(ENTRY_BLOCK_PTR == bb)
      sprintf(extra_BB, "\\nENTRY_BLOCK");
    else 
      if(EXIT_BLOCK_PTR == bb)
	sprintf(extra_BB, "\\nEXIT_BLOCK"); 
    
    fprintf(g_out, "FUNC%d_BB_%d [label=\"_BB_ %d %s\" shape=circle color=red] \n", 
	    current_function_funcdef_no,
	    bb->index, 
	    bb->index, 
	    extra_BB);
    
    gimple prev_stmt = NULL;
    
    for (g_stmt_iter = gsi_start_bb(bb); !gsi_end_p(g_stmt_iter); gsi_next(&g_stmt_iter))
      {
	g_stmt = gsi_stmt(g_stmt_iter);
	
	fprintf(g_out, "FUNC%d_G_%d [label=\"%s _@_ %s:%d UID : %d\"] \n",
		current_function_funcdef_no, 
		gimple_uid(g_stmt), 
		gimple_code_name[gimple_code(g_stmt)], 
		gimple_filename(g_stmt), 
		gimple_lineno(g_stmt), 
		gimple_uid(g_stmt));
	
	fprintf(g_out, "FUNC%d_BB_%d -> FUNC%d_G_%d [color=red]\n", 
		current_function_funcdef_no, 
		bb->index, 
		current_function_funcdef_no, 
		gimple_uid(g_stmt));
	
	if(prev_stmt)
	  fprintf(g_out, "FUNC%d_G_%d -> FUNC%d_G_%d\n", 
		  current_function_funcdef_no, 
		  gimple_uid(prev_stmt), 
		  current_function_funcdef_no, 
		  gimple_uid(g_stmt));
	
	prev_stmt = g_stmt;
	
	for(int i = 0; i < gimple_num_ops(g_stmt); i++)
	  {
	    if ((op = gimple_op(g_stmt, i)))
	      {
		char parent[MAX_STR];
		
		sprintf(parent, "FUNC%d_G_%d",  
			current_function_funcdef_no, 
			gimple_uid(g_stmt));
		
		span_tree_op(op, parent);
	      }   
	  }
      }
    
    //Walk through the basic bloc edges
    edge          target;
    edge_iterator edge_it;
    
    FOR_EACH_EDGE(target, edge_it, bb->succs)
      {
	fprintf(g_out, "FUNC%d_BB_%d -> FUNC%d_BB_%d [color=green]\n", 
		current_function_funcdef_no, 
		bb->index, 
		current_function_funcdef_no, 
		target->dest->index);
      }
  }
  
  return 0;
}

//Put the functions to instrument in the list & check the grammar : ['(' | eps] FCT [,FCT]* [')' | eps]
//Possible lists format : (f1, f2, f3) OR f1, f2, f3. The parenthesis are not required ! 
static void check_pragma(cpp_reader *ARG_UNUSED(dummy))
{
  tree t;
  enum cpp_ttype token;
  bool expect_close_paren = false;
  
  //Check if pragma is inside a function !
  if (cfun)
    {
      //const char *f_name = gimple_decl_printable_name(cfun->decl, 3); //get function's prototype !
      
      cpp_error(dummy, CPP_DL_FATAL, 
		"%<#pragma instrument function%> is not allowed inside functions");
      
      return;
    }
  
  token = pragma_lex(&t);
  
  //If '(' then we're expecting ')'  
  if (token == CPP_OPEN_PAREN)
    expect_close_paren = true, 
    token = pragma_lex(&t);
  
  if (token == CPP_NAME)
    {
      //Add to list !
      if (f_lookup(IDENTIFIER_POINTER(t)) == -1)
	strcpy(f_list[f_nb], IDENTIFIER_POINTER(t)), f_mask[f_nb++] = 0;
      else
	cpp_warning(dummy, CPP_W_WARNING_DIRECTIVE, 
		    "%<#pragma instrument function%> function already specified for instrumentation !");
      
      token = pragma_lex(&t);
      
      while (token == CPP_COMMA)
	{
	  token = pragma_lex(&t);
	  
	  if (token == CPP_NAME)
	    {
	      //Add to list !
	      if (f_lookup(IDENTIFIER_POINTER(t)) == -1)
		strcpy(f_list[f_nb], IDENTIFIER_POINTER(t)), f_mask[f_nb++] = 0;
	      else
		cpp_warning(dummy, CPP_W_WARNING_DIRECTIVE, 
			      "%<#pragma instrument function%> function already specified for instrumentation !");
	      
	      token = pragma_lex(&t);
	    }
	  else
	    {
	      cpp_error(dummy, CPP_DL_FATAL, 
			"%<#pragma instrument function%> is not a string !");
	      return;
	    }
	}
      
      if (expect_close_paren)
	{
	  if (token != CPP_CLOSE_PAREN)
	    {
	      cpp_error(dummy, CPP_DL_FATAL, 
			"%<#pragma instrument function%> ')' expected !");
	      return;
	    }
	}
      else
	if (token == CPP_CLOSE_PAREN)
	  {
	    cpp_error(dummy, CPP_DL_FATAL, 
		      "%<#pragma instrument function%> ')' not expected !");
	    return;
	  }
	else
	  if (token == CPP_NAME)
	    {
	      cpp_error(dummy, CPP_DL_FATAL, 
			"%<#pragma instrument function%> token not expected !");
	      return;
	    }
    }
  else
    {
      cpp_error(dummy, CPP_DL_FATAL, 
		"%<#pragma instrument function%> is not a string !");
      return;
    }
}

//
void insert_zebu_call(basic_block bb, int pos)
{
  const char *f_name = gimple_decl_printable_name(cfun->decl, 1); //Get funtion's name !
  
  //Return type first, then parameters ...
  tree   p_type                    = build_function_type_list(unsigned_type_node, ptr_type_node, NULL_TREE);
  tree   p_func                    = build_fn_decl((pos == INS_ENTRY) ? "zebu_entry_instru" : "zebu_exit_instru", p_type);
  tree   t_f_name                  = build_string_literal(strlen(f_name) + 1, f_name);
  gimple fct_call                  = gimple_build_call(p_func, 1, t_f_name);
  gimple_stmt_iterator g_stmt_iter = (pos == INS_ENTRY) ? gsi_start_bb(bb) : gsi_last_bb(bb);
 
  gsi_insert_before(&g_stmt_iter, fct_call, GSI_NEW_STMT);
}

//Zebu 
unsigned int zebu_exec()
{
  int f_pos;
  const char *f_name = gimple_decl_printable_name(cfun->decl, 1);

  if ((f_pos = f_lookup(f_name)) != -1)
    { 
      edge          e;
      basic_block   bb;
      edge_iterator e_iter;
      
      //Update instrumentation mask !
      f_mask[f_pos] = 1;
      
      //Get the ENTRY_BB and insert at the successors !
      bb = ENTRY_BLOCK_PTR;
      FOR_EACH_EDGE(e, e_iter, bb->succs) //Predecessors
	{
	  insert_zebu_call(e->dest, INS_ENTRY);
	  printf("%s instrumented at entry !\n", f_name);
	}
      
      //Get the EXIT_BB and insert at the predecessors !
      bb = EXIT_BLOCK_PTR;
      FOR_EACH_EDGE(e, e_iter, bb->preds) //Successors
	{
	  insert_zebu_call(e->src, INS_EXIT); 
	  printf("%s instrumented at exit !\n", f_name);
	}
    }
  
  return 0;
}

//
bool zebu_plug_gate()
{ return true; }

//
unsigned int zebu_plug_exec()
{
  cfg_exec();
  zebu_exec();
  //load_store_exec();
  
  return 0;
}

//Clean up & close everything !
void plugin_release(void *gcc_data, void *user_data)
{
  fprintf(g_out,"\n}\n");
  fclose(g_out);

  fprintf(m_out, "\nGLOBAL PROGRAM stats :\n"
	         "gload : %d  gstore : %d\n", gload, gstore);
  fclose(m_out);
  
  for (int i = 0; i < f_nb; i++)
    if (f_mask[i] == 0)
      printf("** WARNING *** function '%s' wasn't istrumented for it wasn't defined !\n", f_list[i]);
}

//New GIMPLE pass ...
static struct opt_pass zebu_pass      =  { GIMPLE_PASS, "zebu", 0, zebu_plug_gate, zebu_plug_exec };

int plugin_init (struct plugin_name_args *plugin_ctx, struct plugin_gcc_version *version)
{
  char file_name[MAX_STR];
  
  strcpy(file_name, main_input_basename);
  strcpy(file_name + strlen(file_name) - 1, "dot");
  
  //Graph file !
  g_out = fopen(file_name, "wb");
  
  strcpy(file_name + strlen(file_name) - 3, "mem");
  
  m_out = fopen(file_name, "wb");
  
  fprintf(g_out,"Digraph G{\n");
  
  printf("Loading Plugin Zebu ...\n");
  
  //Register the 
  c_register_pragma("instrument", "function", check_pragma);
  
  //Fill in new pass informations for zebu pass
  struct register_pass_info new_zebu_pass;
 
  //
  new_zebu_pass.pass = &zebu_pass;             
  new_zebu_pass.reference_pass_name = "cfg"; //"*record_bounds";
  new_zebu_pass.ref_pass_instance_number = 1;   
  new_zebu_pass.pos_op = PASS_POS_INSERT_AFTER; 
  
  //Ask the pass manager to register the pass, nicely :D 
  register_callback(plugin_ctx->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &new_zebu_pass);
  
  //Register plugin information !
  register_callback(plugin_ctx->base_name, PLUGIN_INFO, NULL, &zebu_plugin_infos);
  
  //Register the cleanup function to call after the plugin is finished [free memory, close files, ...]
  register_callback(plugin_ctx->base_name, PLUGIN_FINISH, plugin_release, NULL);
  

  return 0;
}

