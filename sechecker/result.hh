/**
 *  @file
 *  Defines the public interface for sechecker module results.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef SECHECKER_RESULT_HH
#define SECHECKER_RESULT_HH

#include "profile.hh"
#include <apol/policy.h>

#include <string>
#include <map>
#include <typeinfo>
#include <iostream>
#include <stdexcept>

namespace sechk
{
	/**
	 * Function to free an element.
	 * @param x The element to free.
	 */
	typedef void (*free_fn) (void *x);
	/**
	 * Function to copy an element.
	 * @param x The element to copy.
	 */
	typedef void *(*dup_fn) (void *x);

	//forward declaration
	enum output_format;

	//! A container for a single arbitrary policy element.
	class element
	{
	      public:
		/**
		 * Create an element. This will create an element form any type of
		 * policy element, file context entry or apol result.
		 * @param T The type of element.
		 * @param data_ The pointer to the data.  as a special case, if a NULL
		 * pointer to void is given, the element is treated as representing an empty set.
		 * @param free_ Function to call to free memory associated with \a data_;
		 * if \a data_ does not need to be freed, pass NULL.
		 * @param dup_ Function to call to copy \a data_; if it is safe to only
		 * copy the pointer address, pass NULL.
		 * @exception std::bad_alloc Unable to duplicate data_.
		 */
		template < typename T > element(T * data_, free_fn free_, dup_fn dup_) throw(std::bad_alloc):_type(typeid(data_))
		{
			if (dup_)
				_data = dup_(reinterpret_cast < void *>(data_));
			else
				 _data = reinterpret_cast < void *>(data_);
			if (!_data && _type != typeid(void *))
				throw std::bad_alloc();
			 _free = free_;
			 _dup = dup_;
		};
		/**
		 * Copy an element.
		 * @param rhs The element to copy.
		 * @post It is safe to destroy both the original and the copy.
		 * @exception std::bad_alloc Unable to duplicate data_.
		 */
		 element(const element & rhs) throw(std::bad_alloc);
		/**
		 * Assignment operator. This performs a deep copy of the element.
		 * @param rhs The element to use as the right hand side of the assignment.
		 * @return The element after assignment.
		 * @exception std::bad_alloc Unable to duplicate data_.
		 */
		const element & operator=(const element & rhs) throw(std::bad_alloc);
		//! Destructor.
		~element();
		/**
		 * Get the element data.
		 * @return Pointer to the element data.
		 */
		const void *data() const;
		/**
		 * Get the element data.
		 * @return Pointer to the element data.
		 */
		void *data();
		/**
		 * Get the type of element.
		 * @return The type of element.
		 */
		const std::type_info & type() const;

		/**
		 * Print the element.
		 * @param out Stream to which to write.
		 * @param pol Policy associated with the element.
		 * @return The stream after writing.
		 */
		 std::ostream & print(std::ostream & out, apol_policy_t * pol) const;

	      private:
		void *_data;	       //!< The data pointer to the policy element.
		const std::type_info & _type;	//! Type of the element.
		free_fn _free;	       //!< Callback to free memory associated with \a _data, or NULL in no memory to free.
		dup_fn _dup;	       //!< Callback to copy \a _data, or NULL if it is safe to copy the pointer directly.
	};

	//! The result set of a module. Populated by module::run().
	class result
	{
	      public:
		//! Entry for a single policy element found by a check.
		class entry
		{
		      public:
			//! Proof that an entry meets the criteria to be included in the results.
			class proof
			{
			      public:
				/**
				 * Create a proof for a result entry.
				 * @param elem The element representing the proof.
				 * @param prefix_ String to prefix to the element when prining the report.
				 */
				proof(const element & elem, const std::string prefix_ = "");
				/**
				 * Copy a proof.
				 * @param rhs The proof to copy
				 */
				 proof(const proof & rhs);
				//! Destructor.
				~proof();

				/**
				 * Get the element representing the proof.
				 * @return The element representing the proof.
				 */
				const element & Element() const;

				/**
				 * Get the prefix string to print before the element.
				 * @return The prefix string.
				 */
				const std::string & prefix() const;

			      private:
				 element _element;	//!< Policy element representing the proof.
				 std::string _prefix;	//!< Prefix to print before the element in the report; it should explain why the element is proof of a result.
			};

			/**
			 * Create a result entry.
			 * @param The element for which the result was found.
			 */
			entry(const element & elem);
			/**
			 * Copy a result entry.
			 * @param rhs The entry to copy.
			 */
			entry(const entry & rhs);
			//! Destructor.
			~entry();

			/**
			 * Get the element for which the result was found.
			 * @return The element for which the result was found.
			 */
			const element & Element() const;
			/**
			 * Get the set of proof for the entry.
			 * @return The set of proof, indexed by proof element data.
			 */
			const std::map < void *, proof > &Proof() const;
			/**
			 * Add proof for an entry.
			 * @param elem Policy element that provides proof that the entry should be part of the results.
			 * @param prefix_ String to prefix to the element when prining the report.
			 * @return The proof added or, if already it exists, the current proof.
			 * @exception std::invalid_argument Type of \a elem conflicts with previously added proof.
			 */
			proof & addProof(const element & elem, const std::string prefix_) throw(std::invalid_argument);

		      private:
			std::map < void *, proof > _proof;	//!< The set of proof entries for this result entry.
			element _element;	//!< The policy element for which the result was found.
		};

		/**
		 * Create a result set for a module.
		 * @param mod_name Name of the module that will populate the results.
		 * @param out_mode Desired amount of output when reporting the results.
		 * @exception std::invalid_argument Invalid output mode requested or empty module name.
		 */
		result(const std::string & mod_name, output_format out_mode = SECHK_OUTPUT_SHORT) throw(std::invalid_argument);
		/**
		 * Copy a result.
		 * @param rhs The result to copy.
		 */
		result(const result & rhs);
		//! Destructor.
		~result();

		/**
		 * Get the current output mode for the results.
		 * @return The current output mode for the results.
		 */
		output_format outputMode() const;
		/**
		 * Set the output mode for the results.
		 * @param out_mode The desired amount of output when reporting the results.
		 * @return The output mode set.
		 * @exception std::invalid_argument Invalid output mode requested.
		 */
		output_format outputMode(output_format out_mode) throw(std::invalid_argument);

		/**
		 * Get the set of entries. Each entry represents the results for a single element.
		 * @return The set of entries, indexed by entry element data.
		 */
		const std::map < void *, entry > &entries() const;
		/**
		 * Add an entry to the results. If an entry for the element already exists,
		 * return a reference to it.
		 * @param elem The element for which to add an entry.
		 * @return The entry added or, if already it exists, the current entry.
		 * @exception std::invalid_argument Type of \a elem conflicts with previously added entry.
		 */
		entry & addEntry(const element & elem) throw(std::invalid_argument);

	      private:
		std::map < void *, entry > _entries;	//! Set of entries.
		output_format _output_mode;	//!< Desired amount of output when reporting the results.
		std::string _module_name;	//!< Name of module that populated the results.
	};
}

#endif				       /* SECHECKER_RESULT_HH */
